#!/usr/bin/env bash
#
# fix_secaudit.sh — READ-ONLY FIX protocol host security auditor (55 checks)
# ---------------------------------------------------------------------------
#  Each check prints a self-contained mini-report:
#      What : what is being inspected
#      Why  : why it matters (the risk if it is wrong)
#      Seen : the actual value/evidence found on THIS host
#      RESULT: PASS / WARN / FAIL with a plain-English explanation
#      Fix  : concrete remediation (shown for WARN/FAIL)
#
#  SAFETY / SCOPE:
#    * NON-DESTRUCTIVE and READ-ONLY. Sends no FIX messages; no spoof/inject/
#      fuzz/replay. Active FIX attacks belong in a SIMULATOR, not here.
#    * -c = passive capture (observe only). -t = TLS scan of YOUR listeners only.
#    * FIX-06 makes ONE benign outbound HTTPS request; disable with NO_EGRESS=1.
#    * Run ON the server, with written authorization, as root/sudo.
#
#  USAGE:
#     sudo EXTRA_DIRS="/opt/eqt" ./fix_secaudit.sh
#     sudo EXTRA_DIRS="/opt/eqt" ./fix_secaudit.sh -t
#     sudo CAPTURE="10.221.36.88:9996" EXTRA_DIRS="/opt/eqt" ./fix_secaudit.sh -c
# ---------------------------------------------------------------------------

FIX_PROC_PATTERN="${FIX_PROC_PATTERN:-Eqt|quickfix|QuickFix|fixengine|fixgw|fix_}"
FIX_PORTS="${FIX_PORTS:-9090 9100 9256 9996 9997 9998 49000 49042 64403}"
CAPTURE="${CAPTURE:-}"
EXTRA_DIRS="${EXTRA_DIRS:-}"
NO_EGRESS="${NO_EGRESS:-0}"

DO_TLS_SCAN=0; DO_CAPTURE=0
while getopts "tch" o; do case "$o" in
  t) DO_TLS_SCAN=1;; c) DO_CAPTURE=1;; h) grep '^#' "$0"|sed 's/^#//'; exit 0;; *);;
esac; done

if [ -t 1 ]; then C_G=$'\e[32m';C_Y=$'\e[33m';C_R=$'\e[31m';C_B=$'\e[36m';C_D=$'\e[2m';C_0=$'\e[0m'
else C_G="";C_Y="";C_R="";C_B="";C_D="";C_0=""; fi
REPORT="fix_secaudit_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
P=0;W=0;F=0;I=0;S=0;CHK=0
log(){ echo "$*" | tee -a "$REPORT" >/dev/null; echo "$*"; }
sect(){ log ""; log "${C_B}================ $* ================${C_0}"; }
chk(){ CHK=$((CHK+1)); printf -v _id "FIX-%02d" "$CHK"; log ""; log "${C_B}[$_id] $*${C_0}"; }
what(){ log "  ${C_D}What${C_0} : $*"; }
why(){  log "  ${C_D}Why ${C_0} : $*"; }
seen(){ log "  ${C_D}Seen${C_0} : $*"; }
fixit(){ log "  ${C_Y}Fix ${C_0} : $*"; }
pass(){ P=$((P+1)); log "  ${C_G}RESULT: PASS${C_0} - $*"; }
warn(){ W=$((W+1)); log "  ${C_Y}RESULT: WARN${C_0} - $*"; }
fail(){ F=$((F+1)); log "  ${C_R}RESULT: FAIL${C_0} - $*"; }
info(){ I=$((I+1)); log "  RESULT: INFO - $*"; }
skip(){ S=$((S+1)); log "  RESULT: SKIP - $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO=""; fi
log "FIX security audit | host=$(hostname) | $(date)"
log "Report file: $REPORT"
[ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ] && log "${C_Y}NOTE: not root and no passwordless sudo - checks touching other users' /proc, keys, and tcpdump will be limited. Re-run with sudo.${C_0}"

# ---- shared discovery ------------------------------------------------------
FIX_PIDS=$(pgrep -f "$FIX_PROC_PATTERN" 2>/dev/null | sort -u)
CFG_FILES=""; KEY_FILES=""; LOG_FILES=""; STORE_FILES=""; BINS=""
if have lsof; then
  for pid in $FIX_PIDS; do
    OF=$($SUDO lsof -p "$pid" 2>/dev/null | awk '{print $NF}')
    CFG_FILES="$CFG_FILES $(echo "$OF"|grep -Ei '\.(cfg|ini|conf|properties|xml)$')"
    KEY_FILES="$KEY_FILES $(echo "$OF"|grep -Ei '\.(pem|key|jks|p12|pfx|crt|cer)$')"
    LOG_FILES="$LOG_FILES $(echo "$OF"|grep -Ei '\.(log|messages)|message|event')"
    STORE_FILES="$STORE_FILES $(echo "$OF"|grep -Ei 'seqnum|\.body|\.header|store|session')"
    BINS="$BINS $($SUDO readlink /proc/$pid/exe 2>/dev/null)"
  done
fi
for d in $EXTRA_DIRS; do [ -d "$d" ] || continue
  CFG_FILES="$CFG_FILES $($SUDO find "$d" -type f \( -name '*.cfg' -o -name '*.ini' -o -name '*.conf' -o -name '*.properties' \) 2>/dev/null)"
  KEY_FILES="$KEY_FILES $($SUDO find "$d" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.jks' -o -name '*.p12' \) 2>/dev/null)"
done
uniq_list(){ echo "$1" | tr ' ' '\n' | sort -u | grep .; }
CFG_FILES=$(uniq_list "$CFG_FILES"); KEY_FILES=$(uniq_list "$KEY_FILES")
LOG_FILES=$(uniq_list "$LOG_FILES"); STORE_FILES=$(uniq_list "$STORE_FILES"); BINS=$(uniq_list "$BINS")
NIC_IPS=$( (ip -br addr 2>/dev/null | awk '{for(i=3;i<=NF;i++) if($i~/^[0-9]/)print $i}' | cut -d/ -f1) 2>/dev/null )
[ -z "$NIC_IPS" ] && NIC_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep .)
cfg_grep(){ [ -n "$CFG_FILES" ] || return 1; $SUDO grep -aiEh "$1" $CFG_FILES 2>/dev/null; }

# ===========================================================================
sect "A. HOST & NETWORK POSITIONING"

chk "Multi-homing / segment separation"
what "How many IP addresses this host has, and on which interfaces."
why  "A FIX host with one leg on the exchange segment and another on the internal/downstream segment is a network boundary. If the two are not properly separated, an attacker who lands on one side can reach the other."
n=$(echo "$NIC_IPS" | grep -c .); seen "$n IP(s): $(echo $NIC_IPS|tr '\n' ' ')"
if [ "$n" -ge 2 ]; then warn "Host is multi-homed - it sits on more than one network."
  fixit "Confirm each IP is on a deliberately separated VLAN/segment (e.g. exchange-facing vs internal). Ensure no unintended routing between them (see FIX-02)."
else pass "Single IP - not acting as a segment bridge."; fi

chk "IPv4 forwarding"
what "The kernel flag net.ipv4.ip_forward - whether this host routes packets between its interfaces."
why  "If forwarding is on, the box can pass traffic between the exchange segment and the internal segment, turning a trading host into an unintended router that defeats network segmentation."
v=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null); seen "ip_forward=$v"
if [ "$v" = "1" ]; then fail "Forwarding is ON - this host can bridge exchange<->internal traffic."
  fixit "sysctl -w net.ipv4.ip_forward=0 ; persist in /etc/sysctl.d/99-fix.conf (net.ipv4.ip_forward=0). Only leave on if this box is an intentional, reviewed router."
else pass "IPv4 forwarding disabled."; fi

chk "IPv6 forwarding"
what "net.ipv6.conf.all.forwarding - the IPv6 equivalent of the previous check."
why  "IPv6 forwarding is often missed and can bridge segments even when IPv4 is locked down."
v=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null); seen "ipv6 forwarding=${v:-absent}"
if [ "$v" = "1" ]; then warn "IPv6 forwarding enabled."
  fixit "sysctl -w net.ipv6.conf.all.forwarding=0 and persist, unless IPv6 routing is intended."
else pass "IPv6 forwarding disabled/absent."; fi

chk "Routing between segments"
what "The number of default routes and any policy routing."
why  "Multiple default routes / ip rules can silently move traffic between the exchange and internal networks."
if have ip; then g=$(ip route 2>/dev/null | grep -c '^default'); seen "$g default route(s)"
  if [ "$g" -gt 1 ]; then warn "More than one default route - policy routing may connect segments."
    fixit "Review 'ip route' and 'ip rule'. Ensure exchange and internal traffic use the intended interfaces only."
  else pass "Single default route."; fi
else seen "ip command not available"; skip "Cannot enumerate routes."; fi

chk "Reverse-path / anti-spoof filter"
what "net.ipv4.conf.all.rp_filter - drops packets arriving on the wrong interface (basic anti-spoofing)."
why  "Without reverse-path filtering, a spoofed-source packet on the internal side could be accepted as if from the exchange side."
rp=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null); seen "rp_filter=$rp (0=off,1=strict,2=loose)"
if [ "$rp" = "1" ] || [ "$rp" = "2" ]; then pass "Reverse-path filtering enabled."
else warn "Reverse-path filtering off."; fixit "sysctl -w net.ipv4.conf.all.rp_filter=1 and persist."; fi

chk "Egress to the public internet (exfil path)"
what "Whether the host can open an outbound connection to the internet (one test HTTPS request)."
why  "A trading host should reach only the exchange and internal downstream. Open internet egress is a data-exfiltration and malware-callback path."
if [ "$NO_EGRESS" = "1" ]; then seen "test skipped (NO_EGRESS=1)"; skip "Egress test disabled by config."
elif have curl; then code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null); seen "HTTP response code: ${code:-none}"
  if [ -n "$code" ] && [ "$code" != "000" ]; then fail "Host reached the internet - direct egress is open."
    fixit "Restrict egress at the host firewall/network to only exchange + downstream IP:port. Default-deny all other outbound."
  else pass "No direct internet egress (blocked or timed out)."; fi
else seen "curl not installed"; skip "Cannot test egress."; fi

chk "Exchange endpoint by hostname vs IP (DNS-MITM surface)"
what "Whether the FIX config connects to the exchange by hostname or by fixed IP."
why  "If it connects by hostname, an attacker who can spoof or poison DNS can redirect your session to a rogue endpoint (MITM). Fixed IPs remove that dependency."
if [ -n "$CFG_FILES" ]; then h=$($SUDO grep -aiEh 'SocketConnectHost|ConnectHost' $CFG_FILES 2>/dev/null | grep -aoiE '=[ ]*[a-z0-9._-]+' | grep -aiE '[a-z]{2,}' | head -3); seen "connect targets: ${h:-none/IP-only}"
  if echo "$h" | grep -qiE '[a-z]{2,}'; then warn "Endpoint uses a hostname - DNS is now part of your trust chain."
    fixit "Prefer connecting by fixed IP, or pin the resolved IP in /etc/hosts and monitor for changes. Ensure the resolver is trusted."
  else pass "Endpoints look like IPs (no DNS dependency)."; fi
else seen "no config files discovered"; skip "Set EXTRA_DIRS to locate configs."; fi

# ===========================================================================
sect "B. FIX PROCESS & BINARY"

chk "FIX process discovery"
what "Which running processes match your FIX stack pattern ($FIX_PROC_PATTERN)."
why  "Everything else keys off these PIDs. If nothing matches, the pattern is wrong and later checks will be empty."
seen "PIDs: ${FIX_PIDS:-none}"
if [ -n "$FIX_PIDS" ]; then info "FIX processes located."
else warn "No matching processes."; fixit "Set FIX_PROC_PATTERN to match your binaries, e.g. FIX_PROC_PATTERN='Eqt|MarketGateway' ./fix_secaudit.sh"; fi

chk "FIX processes not running as root"
what "The OS user each FIX component runs as."
why  "If the FIX engine runs as root, any code-execution bug in message parsing gives an attacker full control of the host. It should run as a dedicated low-privilege account."
if [ -n "$FIX_PIDS" ]; then for pid in $FIX_PIDS; do u=$(ps -o user= -p "$pid" 2>/dev/null|tr -d ' '); seen "pid=$pid user=$u"
    if [ "$u" = "root" ]; then fail "pid=$pid runs as ROOT."
      fixit "Run this component under a dedicated non-root service account with only the files/ports it needs."
    else pass "pid=$pid runs as non-root '$u'."; fi; done
else skip "No FIX PIDs to inspect."; fi

chk "Shared service account across components"
what "Whether all FIX components run under the same account."
why  "If the market gateway, logger and replicator share one account, compromising any one gives access to all - no privilege separation."
if [ -n "$FIX_PIDS" ]; then us=$(for pid in $FIX_PIDS; do ps -o user= -p "$pid" 2>/dev/null|tr -d ' '; done|sort -u); seen "accounts in use: $(echo $us|tr '\n' ' ')"
  if [ "$(echo "$us"|grep -c .)" -eq 1 ]; then warn "All components share account '$us'."
    fixit "Consider separate accounts per role so a breach of one component doesn't expose the others' keys/data."
  else pass "Components use distinct accounts."; fi
else skip "No FIX PIDs."; fi

chk "Process umask"
what "The umask of each FIX process - controls default permissions on files it creates (logs, stores)."
why  "A loose umask means new message logs / sequence stores are created group- or world-readable, leaking order data."
if [ -n "$FIX_PIDS" ]; then for pid in $FIX_PIDS; do um=$($SUDO grep -a Umask /proc/$pid/status 2>/dev/null|awk '{print $2}'); [ -z "$um" ] && continue; seen "pid=$pid umask=$um"
    if [ "$um" = "0077" ] || [ "$um" = "0027" ]; then pass "pid=$pid umask=$um (restrictive)."
    else warn "pid=$pid umask=$um - new files may be group/other-readable."; fixit "Start the service with 'umask 0077' (or 0027) so created logs/stores are owner-only."; fi; done
else skip "No FIX PIDs."; fi

chk "Binary hardening (NX / PIE)"
what "Whether the FIX binary was compiled with modern exploit mitigations."
why  "A C/C++ FIX engine parses untrusted bytes. Without NX (non-executable stack) and PIE (address randomization), a parser bug is far easier to turn into code execution."
if [ -n "$BINS" ]; then for b in $BINS; do [ -e "$b" ] || continue
    if have checksec; then r=$(checksec --file="$b" 2>/dev/null|tail -1); seen "$b -> $r"; info "checksec output recorded."
    elif have readelf; then nx=$($SUDO readelf -l "$b" 2>/dev/null|grep -c 'GNU_STACK.*RWE'); pie=$($SUDO readelf -h "$b" 2>/dev/null|grep -c 'DYN'); seen "$b nx_stack=$([ $nx -eq 0 ]&&echo yes||echo NO) pie=$([ $pie -gt 0 ]&&echo yes||echo no)"
      [ "$nx" -eq 0 ] && pass "$b has non-executable stack." || { fail "$b has an executable stack."; fixit "Rebuild with -z noexecstack; upgrade the FIX engine build."; }
      [ "$pie" -gt 0 ] && pass "$b is position-independent (PIE)." || { warn "$b is not PIE."; fixit "Rebuild with -fPIE -pie for address-space randomization."; }
    else seen "no checksec/readelf"; skip "Cannot assess $b."; fi; done
else skip "No binaries resolved."; fi

chk "Linked TLS library (CVE surface)"
what "Which SSL/TLS library the FIX binary is linked against, and its version."
why  "Your transport security is only as strong as this library. An outdated OpenSSL pulls in known, exploitable CVEs regardless of FIX config."
if [ -n "$BINS" ] && have ldd; then for b in $BINS; do libs=$($SUDO ldd "$b" 2>/dev/null|grep -iE 'libssl|libcrypto|libgnutls'|awk '{print $3}'|sort -u|head -2)
    for l in $libs; do vv=$(strings "$l" 2>/dev/null|grep -m1 -iE 'OpenSSL [0-9]|GnuTLS [0-9]'); seen "$b -> $l ${vv:+[$vv]}"; done
    [ -n "$libs" ] && info "Look up the reported version against CVE databases." || skip "No TLS lib linked (or static)."; done
else skip "ldd/binary unavailable."; fi

chk "FIX engine / version identification"
what "The FIX engine product and version embedded in the binary."
why  "Known FIX-engine CVEs (parser crashes, memory bugs) are version-specific. You must know exactly what you run to check it."
if [ -n "$BINS" ]; then for b in $BINS; do v=$(strings "$b" 2>/dev/null|grep -im1 -E 'quickfix|onixs|b2bits|cameronfix|fixengine|version [0-9]'); seen "$b -> ${v:-no version string}"
    [ -n "$v" ] && info "Search this engine+version for published CVEs and patch advisories." || skip "No version string in $b."; done
else skip "No binaries."; fi

# ===========================================================================
sect "C. SECRETS EXPOSURE"

mask(){ sed -E 's/((password|passwd|secret|apikey|api_key|token|554)([=:] *))[^ |]+/\1***REDACTED***/Ig'; }
scan(){ $SUDO grep -aInEi 'password|passwd|secret|apikey|api_key|token|BEGIN [A-Z ]*PRIVATE KEY|(^|\|)554=' "$1" 2>/dev/null | mask | head -3; }

chk "Cleartext secrets in configs"
what "FIX/app config files searched for embedded passwords, keys or API tokens (values shown REDACTED)."
why  "Credentials baked into config travel with the tarball and backups. Anyone who reads the file - or the archive - gets your exchange login."
h=0; for f in $CFG_FILES; do o=$(scan "$f"); [ -n "$o" ] && { h=1; seen "$f"; echo "$o"|sed 's/^/         /'|tee -a "$REPORT"; }; done
if [ "$h" -eq 1 ]; then fail "Secret-like data found in config(s)."
  fixit "Move credentials/keys to a secrets manager or an owner-only (600) file outside the deployment. Never ship secrets in the tar.gz."
elif [ -n "$CFG_FILES" ]; then pass "No cleartext secrets in configs."; else skip "No configs (set EXTRA_DIRS)."; fi

chk "Cleartext secrets in logs"
what "Log and FIX message files searched for passwords and the FIX Password field (tag 554)."
why  "FIX logon logs frequently capture the password (554). Logs are widely readable and long-retained, so a secret here is a lasting exposure."
h=0; for f in $LOG_FILES; do o=$(scan "$f"); [ -n "$o" ] && { h=1; seen "$f contains secret-like data (masked)"; }; done
if [ "$h" -eq 1 ]; then fail "Secret-like data found in log(s)."
  fixit "Mask tag 554/credentials in the engine's log config; rotate any exposed password; restrict log permissions (see FIX-54)."
elif [ -n "$LOG_FILES" ]; then pass "No cleartext secrets in logs."; else skip "No logs discovered."; fi

chk "Secrets in process environment"
what "Each FIX process's environment variables (/proc/PID/environ) checked for credential-like names."
why  "Passwords passed via env vars are visible to anyone who can read /proc for that user and often leak into crash dumps and process listings."
if [ -n "$FIX_PIDS" ]; then h=0; for pid in $FIX_PIDS; do e=$($SUDO tr '\0' '\n' </proc/$pid/environ 2>/dev/null|grep -iE 'pass|secret|token|key='); [ -n "$e" ] && { h=1; seen "pid=$pid has credential-like env vars (masked)"; }; done
  if [ "$h" -eq 1 ]; then fail "Secrets present in process environment."; fixit "Pass secrets via a file or secrets manager, not environment variables."
  else pass "No secret-like environment variables."; fi
else skip "No FIX PIDs."; fi

chk "Secrets in shell history"
what "Shell history files checked for typed passwords / credential flags."
why  "Operators sometimes type passwords on the command line; these persist in history and are a common easy win for an attacker."
hh=0; for f in /home/*/.bash_history /root/.bash_history "$HOME/.bash_history"; do [ -r "$f" ] || continue
  $SUDO grep -aiE 'password|passwd|-p .+|secret' "$f" >/dev/null 2>&1 && { hh=1; seen "$f has credential-like commands"; }; done
if [ "$hh" -eq 1 ]; then warn "Credential-like commands found in history."; fixit "Scrub the history files; educate operators to avoid secrets on the CLI; rotate anything exposed."
else pass "No obvious credentials in shell history."; fi

chk "Core dumps present on disk"
what "Whether crash core-dump files exist on the filesystem."
why  "A core dump is a snapshot of process memory - it can contain private keys, passwords and live order data in cleartext."
cds=$($SUDO find / -maxdepth 4 -name 'core*' -type f 2>/dev/null|head -5); seen "${cds:-none found}"
if [ -n "$cds" ]; then warn "Core dump file(s) present."; fixit "Delete them securely; disable core dumps for the service (see next check)."
else pass "No core dumps found."; fi

chk "Core dumps disabled (ulimit)"
what "The core-dump size limit for the current/service context."
why  "If core dumps are enabled, a future crash will write process memory (keys, orders) to disk."
cl=$(ulimit -c); seen "ulimit -c = $cl"
if [ "$cl" = "0" ]; then pass "Core dumps disabled."
else warn "Core dumps enabled."; fixit "Set 'ulimit -c 0' for the service, or systemd 'LimitCORE=0'."; fi

# ===========================================================================
sect "D. FILE PERMISSIONS"

chk "Private key / cert permissions"
what "Permissions on TLS private-key and certificate files."
why  "A private key readable by group/other lets any local user impersonate your session to the exchange. Keys must be owner-only (600/400)."
if [ -n "$KEY_FILES" ]; then for f in $KEY_FILES; do [ -e "$f" ] || continue; pm=$($SUDO stat -c '%a %U:%G' "$f" 2>/dev/null)
    case "$f" in *.key|*.pem|*.p12|*.pfx|*.jks)
      if [ -n "$($SUDO find "$f" -perm /077 2>/dev/null)" ]; then seen "$f = $pm"; fail "$f is accessible by group/other."; fixit "chmod 600 $f ; chown <service-user> $f"
      else seen "$f = $pm"; pass "$f restricted to owner."; fi ;;
    *) seen "$f = $pm (cert)"; info "Certificate (public) - permissions less critical." ;; esac; done
else warn "No key files found."; fixit "If the session is meant to be TLS, locate the key/cert and confirm they exist and are protected. Set EXTRA_DIRS."; fi

chk "Config file permissions"
what "Whether config files are writable by group/other."
why  "A writable config lets a local attacker point the client at a rogue endpoint, disable TLS, or change credentials."
if [ -n "$CFG_FILES" ]; then for f in $CFG_FILES; do pm=$($SUDO stat -c '%a %U:%G' "$f" 2>/dev/null)
    if [ -n "$($SUDO find "$f" -perm /022 2>/dev/null)" ]; then seen "$f = $pm"; warn "$f is group/other-writable."; fixit "chmod o-w,g-w $f (target 640 or 600)."
    else seen "$f = $pm"; pass "$f not group/other-writable."; fi; done
else skip "No configs."; fi

chk "Sequence / message store permissions"
what "Permissions on the FIX message store and sequence-number files."
why  "These hold full order history AND the session sequence state. If writable, an attacker can tamper with sequence numbers to force replays or desync; if readable, order flow leaks."
if [ -n "$STORE_FILES" ]; then for f in $STORE_FILES; do [ -e "$f" ] || continue; pm=$($SUDO stat -c '%a %U:%G' "$f" 2>/dev/null)
    if [ -n "$($SUDO find "$f" -perm /022 2>/dev/null)" ]; then seen "$f = $pm"; fail "$f is writable by group/other - enables sequence tamper/replay."; fixit "chmod 600 $f ; restrict the whole store directory to the service user."
    elif [ -n "$($SUDO find "$f" -perm /044 2>/dev/null)" ]; then seen "$f = $pm"; warn "$f is readable by group/other - order-history exposure."; fixit "chmod o-r,g-r $f"
    else seen "$f = $pm"; pass "$f restricted to owner."; fi; done
else warn "No message/sequence store located."; fixit "Confirm where the engine persists sequence state (FileStorePath) and lock it to the service user. Set EXTRA_DIRS."; fi

chk "World-writable files in install dirs"
what "Any world-writable file under your install directories."
why  "World-writable files under the app tree let any local user swap a binary, config or script the service later runs."
if [ -n "$EXTRA_DIRS" ]; then ww=$($SUDO find $EXTRA_DIRS -type f -perm -002 2>/dev/null|head -5); seen "${ww:-none}"
  if [ -n "$ww" ]; then fail "World-writable files present."; fixit "chmod o-w on the listed files; audit how they became writable."
  else pass "No world-writable files in install dirs."; fi
else skip "Set EXTRA_DIRS to scan the install tree."; fi

chk "SUID/SGID binaries in install dirs"
what "SUID/SGID files under the install tree."
why  "An unnecessary SUID/SGID binary is a classic local privilege-escalation vector."
if [ -n "$EXTRA_DIRS" ]; then sg=$($SUDO find $EXTRA_DIRS -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null|head -5); seen "${sg:-none}"
  if [ -n "$sg" ]; then warn "SUID/SGID files present."; fixit "Remove the setuid/setgid bit unless strictly required (chmod u-s,g-s)."
  else pass "No SUID/SGID in install dirs."; fi
else skip "Set EXTRA_DIRS."; fi

# ===========================================================================
sect "E. TLS & FIX CONFIG SEMANTICS"

chk "TLS/SSL enabled in engine config"
what "Whether the FIX config turns on transport encryption at all."
why  "FIX is plaintext by design. If TLS is not enabled here, credentials and orders cross the wire in the clear."
if [ -n "$CFG_FILES" ]; then r=$(cfg_grep 'SocketUseSSL|SSLEnable|SSLProtocol|CertificateFile|SocketPrivateKey'); seen "${r:-no TLS keys found}"
  if echo "$r"|grep -qiE 'SocketUseSSL *= *Y|SSLEnable *= *Y|SSLProtocol|CertificateFile'; then pass "TLS settings present in config."
  else warn "No TLS settings found."; fixit "Enable SocketUseSSL=Y and configure cert/key/CA, or confirm TLS is terminated by a trusted proxy/network."; fi
else skip "No configs."; fi

chk "TLS not explicitly disabled"
what "Whether the config explicitly turns TLS off."
why  "An explicit SocketUseSSL=N means the session is deliberately plaintext - a high-severity exposure."
r=$(cfg_grep 'SocketUseSSL *= *N|SSLEnable *= *N'); seen "${r:-not disabled}"
if [ -n "$r" ]; then fail "TLS explicitly disabled - FIX traffic is plaintext."; fixit "Set SocketUseSSL=Y and configure certificates; coordinate cutover with the exchange."
else pass "TLS not disabled in config."; fi

chk "Certificate validation not disabled"
what "Whether certificate/peer validation is switched off."
why  "TLS without validation still encrypts but accepts ANY certificate - a MITM can present a fake cert and read/alter everything."
r=$(cfg_grep 'SSLValidateCertificates *= *N|SSLVerifyClient *= *none|VerifyMode *= *0'); seen "${r:-validation not disabled}"
if [ -n "$r" ]; then fail "Certificate validation appears disabled - MITM risk."; fixit "Enable full chain + hostname validation (SSLValidateCertificates=Y); load the exchange CA; consider cert pinning."
else pass "No validation-off flags found."; fi

chk "EncryptMethod / plaintext posture"
what "The FIX EncryptMethod (tag 98) setting and whether TLS backs it."
why  "EncryptMethod=0 (None) is normal ONLY when TLS handles encryption at transport. EncryptMethod=0 with no TLS means fully plaintext FIX."
em=$(cfg_grep 'EncryptMethod'); seen "${em:-EncryptMethod not set}"
if echo "$em"|grep -qE '= *0'; then
  if cfg_grep 'SocketUseSSL *= *Y' >/dev/null; then pass "EncryptMethod=0 but TLS at transport (expected modern setup)."
  else warn "EncryptMethod=0 and TLS not confirmed - messages may be plaintext."; fixit "Rely on TLS at transport (SocketUseSSL=Y). Do not use legacy FIX field-level encryption."; fi
elif [ -n "$em" ]; then info "Non-zero EncryptMethod set - legacy; verify it's actually intended (TLS is preferred)."
else skip "EncryptMethod not set."; fi

chk "Weak TLS protocol pinned in config"
what "Whether the config pins a deprecated TLS/SSL protocol version."
why  "SSLv3 / TLS 1.0 / TLS 1.1 have known weaknesses and should not be used; only TLS 1.2/1.3 are acceptable."
r=$(cfg_grep 'SSLProtocol.*(SSLv3|TLSv1\.1|TLSv1[^.])'); seen "${r:-no deprecated protocol pinned}"
if [ -n "$r" ]; then fail "Deprecated TLS protocol referenced."; fixit "Require TLS 1.2 minimum, prefer 1.3; remove SSLv3/TLS1.0/1.1."
else pass "No deprecated TLS protocol pinned."; fi

chk "Referenced cert/key files exist"
what "Whether cert/key paths named in the config actually exist on disk."
why  "A missing cert/key path often means the engine silently falls back to no/def­ault TLS, or fails open."
miss=0; for f in $(cfg_grep 'CertificateFile|SocketPrivateKey|SSLCACert' | grep -aoE '/[^ ]+'); do if [ ! -e "$f" ]; then miss=1; seen "MISSING: $f"; fi; done
if [ "$miss" -eq 1 ]; then warn "A referenced cert/key file is missing."; fixit "Fix the path or install the file; confirm the engine isn't falling back to plaintext."
else pass "Referenced cert/key files present (or none referenced)."; fi

chk "Message-validation switches"
what "Whether the engine's inbound-validation options are turned off."
why  "Disabling ValidateFieldsOutOfOrder / ValidateUserDefinedFields / ValidateFieldsHaveValues makes the parser accept malformed messages - a larger attack surface and a downstream-injection risk."
r=$(cfg_grep 'ValidateFieldsOutOfOrder *= *N|ValidateUserDefinedFields *= *N|ValidateFieldsHaveValues *= *N'); seen "${r:-no validation disabled}"
if [ -n "$r" ]; then fail "One or more FIX validation checks are disabled."; fixit "Re-enable field validation unless the exchange spec specifically requires otherwise."
else pass "No validation switches disabled."; fi

chk "HeartBtInt sanity"
what "The configured heartbeat interval (tag 108)."
why  "A very long heartbeat means a dropped or hijacked session takes a long time to detect."
hb=$(cfg_grep 'HeartBtInt' | grep -aoE '[0-9]+' | head -1); seen "HeartBtInt=${hb:-not set} sec"
if [ -n "$hb" ]; then if [ "$hb" -gt 60 ] 2>/dev/null; then warn "Heartbeat interval is long (${hb}s)."; fixit "Use a shorter interval (e.g. 30s) per exchange guidance so dead/hijacked sessions are detected quickly."
  else pass "Heartbeat interval reasonable (${hb}s)."; fi
else skip "HeartBtInt not set."; fi

chk "Reset-on-logon/logout policy"
what "Whether ResetOnLogon/Logout/Disconnect are enabled."
why  "Sequence-reset behaviour affects replay and gap handling. It must match the exchange's spec exactly, or you risk missed messages or accepted replays."
r=$(cfg_grep 'ResetOnLogon *= *Y|ResetOnLogout *= *Y|ResetOnDisconnect *= *Y'); seen "${r:-no reset-on-* flags}"
if [ -n "$r" ]; then info "Reset-on-* enabled - verify this matches the exchange specification."
else pass "No aggressive reset-on-* flags set."; fi

chk "Session schedule (connect window)"
what "Whether the session has a defined active time window (StartTime/EndTime)."
why  "A 24x7 session with no schedule can be connected outside trading hours, widening the window for misuse."
sch=$(cfg_grep 'StartTime|EndTime'); seen "${sch:-no schedule set}"
if [ -n "$sch" ]; then info "Session schedule configured - confirm it matches intended trading hours."
else warn "No session schedule."; fixit "Set StartTime/EndTime to the intended trading window if the exchange supports it."; fi

# ===========================================================================
sect "F. NETWORK EXPOSURE"

chk "FIX ports bound to 0.0.0.0"
what "Whether any FIX listener is bound to all interfaces (0.0.0.0) instead of one address."
why  "On a multi-homed trading host, a 0.0.0.0 bind exposes the listener on EVERY segment - including ones it shouldn't face."
if have ss; then any=0; for p in $FIX_PORTS; do l=$($SUDO ss -tlnp 2>/dev/null|awk -v x=":$p\$" '$4~x'); [ -z "$l" ] && continue; any=1
    if echo "$l"|grep -qE '(0\.0\.0\.0|\*):'"$p"; then seen "port $p -> 0.0.0.0 (all interfaces)"; warn "port $p bound to all interfaces."; fixit "Bind the listener to the specific internal IP it should serve, not 0.0.0.0."
    else seen "port $p -> specific address"; pass "port $p bound to a specific address."; fi; done
  [ "$any" -eq 0 ] && skip "None of the configured FIX_PORTS are listening."
else skip "ss unavailable."; fi

chk "Full TCP listener inventory"
what "Every TCP port this host is listening on (written to the report)."
why  "Unexpected listeners are extra attack surface; the inventory is your baseline to spot anything that shouldn't be there."
if have ss; then $SUDO ss -tlnp 2>/dev/null | tee -a "$REPORT" >/dev/null; c=$($SUDO ss -tlnp 2>/dev/null|grep -c LISTEN); seen "$c listening sockets (full list in report)"; info "Review the inventory for services that aren't part of the FIX stack."
else skip "ss unavailable."; fi

chk "Passive cleartext-FIX detection (observe-only)"
what "Sniffs a few packets of ONE session (that you specify) to see if FIX is on the wire in cleartext."
why  "This is the definitive proof of whether the session is actually encrypted, independent of what the config claims."
if [ "$DO_CAPTURE" = "1" ] && [ -n "$CAPTURE" ] && have tcpdump; then CH=${CAPTURE%:*}; CP=${CAPTURE##*:}
  d=$($SUDO timeout 15 tcpdump -i any -A -s0 -c 40 "host $CH and port $CP" 2>/dev/null)
  if echo "$d"|grep -aqE '8=FIXT?\.[0-9]'; then seen "found '8=FIX...' in cleartext on $CH:$CP"; fail "CLEARTEXT FIX detected - session is unencrypted."; fixit "Enable TLS on this session urgently; treat any credentials/orders seen as exposed."
  elif [ -n "$d" ]; then seen "no FIX tags visible on $CH:$CP"; pass "Traffic is not cleartext FIX (looks encrypted)."
  else seen "no packets captured (idle session?)"; info "No traffic seen in the window."; fi
else seen "capture not requested"; skip "Enable with CAPTURE=IP:PORT ... -c using an IN-SCOPE session (internal hub/downstream), never an exchange port."; fi

chk "TLS scan of own listeners (active, own IPs only)"
what "Runs a TLS cipher/protocol scan against YOUR OWN listeners only."
why  "Confirms your listeners enforce strong TLS versions/ciphers. Restricted to your own IPs so it never touches the exchange."
if [ "$DO_TLS_SCAN" = "1" ]; then done_any=0; for ip in $NIC_IPS; do for p in $FIX_PORTS; do
    $SUDO ss -tlnp 2>/dev/null|awk -v a="$ip:$p" '$4==a{f=1}END{exit !f}' || continue; done_any=1; seen "scanning own listener $ip:$p"
    if have testssl.sh; then testssl.sh --quiet --protocols "$ip:$p" 2>/dev/null|tee -a "$REPORT"; info "testssl results for $ip:$p in report."
    elif have nmap; then nmap --script ssl-enum-ciphers -p "$p" "$ip" 2>/dev/null|tee -a "$REPORT"; info "nmap ssl-enum results for $ip:$p in report."
    else skip "Install testssl.sh or nmap to scan."; fi; done; done
  [ "$done_any" -eq 0 ] && skip "No own listeners matched FIX_PORTS."
else seen "not requested"; skip "Enable with -t (scans YOUR listeners only, never exchange ports)."; fi

# ===========================================================================
sect "G. HOST HARDENING"

chk "systemd sandbox exposure"
what "The systemd 'security exposure' score for each FIX service unit."
why  "systemd can sandbox a service (restrict filesystem, capabilities, syscalls). A high exposure score means little containment if the process is compromised."
if have systemd-analyze && [ -n "$FIX_PIDS" ]; then found=0; for pid in $FIX_PIDS; do u=$(grep -aoE '[a-zA-Z0-9_.@-]+\.service' /proc/$pid/cgroup 2>/dev/null|head -1); [ -z "$u" ] && continue; found=1
    sc=$(systemd-analyze security "$u" 2>/dev/null|grep -i 'Overall exposure'|awk '{print $NF}'); seen "$u exposure=$sc (0=locked down, 10=none)"
    info "Lower is better; aim under 5. Add hardening directives to the unit if high."; done
  [ "$found" -eq 0 ] && skip "No systemd unit resolved for the FIX PIDs."
else skip "systemd-analyze unavailable."; fi
[ -n "$FIX_PIDS" ] && fixit "Harden the unit: NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes, ReadWritePaths=<store/log dirs>, CapabilityBoundingSet=."

chk "Mandatory access control (SELinux/AppArmor)"
what "Whether a MAC system is enforcing on this host."
why  "SELinux/AppArmor confine the process even if it's exploited. Without it, a compromise has free rein of whatever the user can access."
if have getenforce; then m=$(getenforce); seen "SELinux=$m"; [ "$m" = "Enforcing" ] && pass "SELinux Enforcing." || { warn "SELinux is $m."; fixit "Set SELinux to Enforcing (setenforce 1; SELINUX=enforcing in /etc/selinux/config)."; }
elif have aa-status; then if $SUDO aa-status >/dev/null 2>&1; then seen "AppArmor loaded"; pass "AppArmor active."; else seen "AppArmor not active"; warn "AppArmor not confirmed."; fixit "Enable AppArmor and load a profile confining the FIX service."; fi
else seen "no MAC tooling"; warn "No SELinux/AppArmor tooling found."; fixit "Deploy SELinux or AppArmor and confine the FIX service."; fi

chk "Firewall egress policy"
what "Whether a host firewall with rules is present."
why  "A default-deny egress firewall that only allows exchange + downstream limits both inbound exposure and outbound exfiltration."
if have nft && $SUDO nft list ruleset >/dev/null 2>&1; then c=$($SUDO nft list ruleset 2>/dev/null|grep -c .); seen "nftables lines=$c"
  [ "$c" -gt 0 ] && { pass "nftables ruleset present."; fixit "Confirm it is default-deny egress, allowing only exchange + downstream IP:port."; } || { warn "nftables empty."; fixit "Add a default-deny egress policy."; }
elif have iptables; then c=$($SUDO iptables -S 2>/dev/null|grep -c .); seen "iptables rules=$c"
  [ "$c" -gt 3 ] && { pass "iptables rules present."; fixit "Verify egress is allow-listed to exchange + downstream only."; } || { warn "iptables largely empty - egress likely open."; fixit "Implement a default-deny egress policy."; }
else seen "no firewall tooling"; warn "No firewall tooling found."; fixit "Deploy nftables/iptables with default-deny egress."; fi

chk "SSH hardening"
what "Key sshd_config settings: root login and password authentication."
why  "Password-based or root SSH login is a common entry point onto a trading host."
scf=/etc/ssh/sshd_config
if [ -r "$scf" ]; then
  if $SUDO grep -qiE '^\s*PermitRootLogin\s+(yes|prohibit-password)' "$scf"; then seen "PermitRootLogin permissive"; warn "Root SSH login not fully disabled."; fixit "Set 'PermitRootLogin no'."
  else seen "PermitRootLogin restricted"; pass "Root SSH login restricted."; fi
  if $SUDO grep -qiE '^\s*PasswordAuthentication\s+no' "$scf"; then seen "PasswordAuthentication no"; pass "SSH password auth disabled (keys only)."
  else seen "PasswordAuthentication not set to no"; warn "SSH password auth enabled."; fixit "Set 'PasswordAuthentication no' and use keys."; fi
else seen "sshd_config unreadable"; skip "Cannot read sshd_config."; fi

chk "Time synchronization (NTP)"
what "Whether the system clock is synchronized."
why  "FIX SendingTime (52) and sequencing depend on an accurate clock; drift causes rejects and breaks audit/forensics."
if have timedatectl; then s=$(timedatectl show -p NTPSynchronized --value 2>/dev/null); seen "NTPSynchronized=$s"
  echo "$s"|grep -qi yes && pass "Clock is NTP-synchronized." || { warn "Clock not synchronized."; fixit "Enable and start chrony/systemd-timesyncd; point at a reliable NTP source."; }
elif have chronyc; then if chronyc tracking 2>/dev/null|grep -i 'Leap status'|grep -qi Normal; then seen "chrony leap=Normal"; pass "chrony synchronized."; else seen "chrony sync uncertain"; warn "chrony sync uncertain."; fixit "Check chrony sources/reachability."; fi
else seen "no NTP tooling"; warn "No NTP tooling found."; fixit "Install and configure chrony."; fi

chk "Pending security updates"
what "Count of outstanding OS security updates."
why  "Unpatched packages (especially OpenSSL/kernel) are directly exploitable regardless of your FIX config."
if have apt-get; then u=$(apt-get -s upgrade 2>/dev/null|grep -c '^Inst.*ecurit'); seen "$u security update(s) pending"
  [ "$u" -gt 0 ] && { warn "$u security updates pending."; fixit "Apply security updates in a change window."; } || pass "No pending security updates."
elif have yum; then u=$(yum -q check-update --security 2>/dev/null|grep -c '.'); seen "$u line(s) from yum security check"
  [ "$u" -gt 0 ] && { warn "Security updates pending."; fixit "Apply 'yum update --security'."; } || pass "No pending security updates."
else seen "no supported package manager"; skip "Cannot check updates."; fi

chk "Kernel currency / uptime"
what "Running kernel version and system uptime."
why  "Very long uptime usually means missed kernel security patches (no reboot after updates)."
seen "kernel=$(uname -r), uptime=$(uptime -p 2>/dev/null || echo unknown)"
info "If uptime is very long, plan a patched-kernel reboot in a maintenance window."

# ===========================================================================
sect "H. PRIVILEGE ESCALATION & LATERAL MOVEMENT"

chk "Service-account sudo rights"
what "Whether the current/service account can escalate via sudo."
why  "If the account running FIX can sudo (especially NOPASSWD), a compromise of the FIX process becomes full root."
sr=$($SUDO -l 2>/dev/null | grep -E 'ALL|NOPASSWD'); seen "${sr:-no broad sudo entries}"
if [ -n "$sr" ]; then warn "Account has sudo rights (ALL/NOPASSWD present)."; fixit "Remove sudo from the FIX service account; it should not be able to escalate."
else pass "No broad sudo rights detected."; fi

chk "SSH trust (authorized_keys)"
what "SSH keys trusted for login on this host."
why  "Trusted keys are lateral-movement paths; an attacker who lands here may pivot to wherever these keys are also accepted."
ak=0; for f in /home/*/.ssh/authorized_keys "$HOME/.ssh/authorized_keys"; do [ -r "$f" ] || continue; c=$($SUDO grep -c . "$f" 2>/dev/null); [ "$c" -gt 0 ] && { ak=1; seen "$f has $c trusted key(s)"; }; done
if [ "$ak" -eq 1 ]; then warn "Trusted SSH keys present."; fixit "Review each key; remove unknown/stale ones; restrict where the service account can log in from."
else pass "No readable authorized_keys with entries."; fi

chk "Cron jobs / systemd timers"
what "Scheduled jobs and timers on the host."
why  "Deploy/log/rotation jobs that touch FIX configs, keys or the tarball are worth reviewing - they can be abused for persistence or to introduce tampered files."
cj=$($SUDO ls /etc/cron.d /etc/cron.daily 2>/dev/null|grep -c .); tm=$(systemctl list-timers --no-legend 2>/dev/null|grep -c .); seen "cron entries=$cj, systemd timers=$tm"
info "Review any job that reads/writes FIX configs, keys, logs, or the deployment tree."

chk "Writable directories in PATH"
what "Any world-writable directory in the current PATH."
why  "A world-writable PATH dir lets an attacker plant a malicious binary that the service runs by name."
wp=0; for d in $(echo "$PATH"|tr ':' ' '); do [ -d "$d" ] || continue; [ -n "$($SUDO find "$d" -maxdepth 0 -perm -002 2>/dev/null)" ] && { wp=1; seen "world-writable PATH dir: $d"; }; done
if [ "$wp" -eq 1 ]; then warn "World-writable directory in PATH."; fixit "chmod o-w on the directory, or remove it from PATH."
else pass "No world-writable PATH directories."; fi

# ===========================================================================
sect "I. AUDIT, MONITORING, INTEGRITY & DEPLOYMENT"

chk "File-integrity monitoring present"
what "Whether a FIM tool (AIDE/Tripwire) is installed."
why  "FIM detects tampering with configs, keys and binaries. Without it, silent modification of your FIX deployment can go unnoticed."
if have aide || have tripwire; then seen "$(command -v aide tripwire 2>/dev/null|tr '\n' ' ')"; pass "File-integrity tool present."
else seen "no aide/tripwire"; warn "No file-integrity monitoring."; fixit "Deploy AIDE/Tripwire and baseline the FIX config/key/binary paths."; fi

chk "auditd coverage of keys/configs"
what "Whether the audit subsystem watches sensitive FIX paths."
why  "Audit rules on keys/configs give you a record of who accessed or changed them - essential for both security and regulation."
if have auditctl; then r=$($SUDO auditctl -l 2>/dev/null | grep -iE '\.key|\.cfg|/etc/ssh|fix'); seen "${r:-no matching audit rules}"
  [ -n "$r" ] && pass "Audit rules cover sensitive paths." || { warn "No audit rules on FIX keys/configs."; fixit "Add auditd watches on the key/config directories."; }
else seen "auditd absent"; warn "auditd not present."; fixit "Install/enable auditd and watch FIX key/config paths."; fi

chk "Remote log forwarding (off-host)"
what "Whether logs are shipped to a remote collector/SIEM."
why  "Logs that only live on the box can be wiped by anyone who compromises it. Off-host copies preserve the evidence trail."
if grep -qsrE '^\*\.\*|@@?[0-9a-zA-Z]' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then seen "remote target configured in rsyslog"; pass "Remote log forwarding configured."
else seen "no remote target found"; warn "No remote log forwarding."; fixit "Forward FIX/audit logs to a central SIEM so they survive host compromise."; fi

chk "Log file permissions"
what "Whether FIX log/message files are readable by group/other."
why  "Message logs contain full order flow and sometimes credentials; they must be owner-only."
if [ -n "$LOG_FILES" ]; then h=0; for f in $LOG_FILES; do [ -n "$($SUDO find "$f" -perm /044 2>/dev/null)" ] && { h=1; seen "$f is group/other-readable ($($SUDO stat -c '%a' "$f" 2>/dev/null))"; }; done
  if [ "$h" -eq 1 ]; then warn "Log files readable by group/other."; fixit "chmod o-r,g-r on the log/message files; fix the service umask (FIX-11)."
  else pass "Log files not group/other-readable."; fi
else skip "No logs discovered."; fi

chk "Deployment integrity (checksum/signature)"
what "Whether a checksum/signature manifest ships alongside the deployment."
why  "A signed/checksummed tarball lets you prove the deployed code wasn't tampered with. No manifest = no integrity guarantee for the tar.gz."
if [ -n "$EXTRA_DIRS" ]; then man=$($SUDO find $EXTRA_DIRS -maxdepth 2 \( -iname '*.sha256*' -o -iname '*.sig' -o -iname 'SHA256SUMS' \) 2>/dev/null|head -3); seen "${man:-no manifest found}"
  if [ -n "$man" ]; then info "Manifest present - verify deployed files against it (sha256sum -c / gpg --verify)."
  else warn "No checksum/signature manifest beside the deployment."; fixit "Publish a SHA-256 + GPG signature for the release tarball and verify it before/after deploy."; fi
else skip "Set EXTRA_DIRS."; fi

# ===========================================================================
sect "SUMMARY"
log ""
log "Checks run: $CHK"
log "  ${C_G}PASS=$P${C_0}   ${C_Y}WARN=$W${C_0}   ${C_R}FAIL=$F${C_0}   INFO=$I   SKIP=$S"
log ""
log "How to read this: each check has What/Why/Seen/RESULT/Fix. Work FAIL first,"
log "then WARN. SKIP usually means a tool was missing or EXTRA_DIRS wasn't set."
log ""
log "Out of scope here (do NOT run against the live exchange session): active FIX"
log "attacks - SenderCompID spoof, SequenceReset, replay, admin-message injection,"
log "malformed-message fuzzing, downstream injection. Run those against a SIMULATOR."
log ""
log "Full report saved to: $REPORT"
[ "$F" -gt 0 ] && exit 2 || exit 0
