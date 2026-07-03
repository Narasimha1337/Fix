#!/usr/bin/env bash
#
# fix_secaudit.sh — READ-ONLY FIX protocol host security auditor (55 checks)
# ---------------------------------------------------------------------------
#  Validates the defensive controls from the FIX 5.0 hardening guide against a
#  live Linux server running a FIX client / gateway stack. Each check has an ID
#  (FIX-NN) so output can be used directly as a findings register.
#
#  SAFETY / SCOPE (read before running):
#    * NON-DESTRUCTIVE and READ-ONLY. Sends no FIX messages; no spoof/inject/
#      fuzz/replay. Active FIX-protocol attacks must run against a SIMULATOR,
#      never a live exchange session — they are intentionally NOT in here.
#    * Optional passive capture (-c) only OBSERVES existing traffic.
#    * Optional TLS scan (-t) targets YOUR OWN listeners only.
#    * One benign outbound HTTPS request is made to test egress (FIX-06); skip
#      with NO_EGRESS=1 if policy forbids any outbound.
#    * Run only with written authorization for THIS host. Run ON the server
#      (needs local /proc, lsof, file perms) — not remotely.
#
#  USAGE:
#     sudo ./fix_secaudit.sh                 # 53 local read-only checks
#     sudo ./fix_secaudit.sh -t              # + TLS-scan own listeners (FIX-39)
#     sudo CAPTURE="10.221.36.88:9996" ./fix_secaudit.sh -c   # + passive sniff
# ---------------------------------------------------------------------------

# ---- CONFIG (edit for your environment) -----------------------------------
FIX_PROC_PATTERN="${FIX_PROC_PATTERN:-Eqt|quickfix|QuickFix|fixengine|fixgw|fix_}"
FIX_PORTS="${FIX_PORTS:-9090 9100 9256 9996 9997 9998 49000 49042 64403}"
CAPTURE="${CAPTURE:-}"                 # "IP:PORT" of ONE in-scope session
EXTRA_DIRS="${EXTRA_DIRS:-}"           # install dir(s) to scan for cfg/keys/logs
NO_EGRESS="${NO_EGRESS:-0}"            # 1 = skip the outbound egress test
# ---------------------------------------------------------------------------

DO_TLS_SCAN=0; DO_CAPTURE=0
while getopts "tch" o; do case "$o" in
  t) DO_TLS_SCAN=1;; c) DO_CAPTURE=1;; h) grep '^#' "$0"|sed 's/^#//'; exit 0;; *);;
esac; done

if [ -t 1 ]; then C_G=$'\e[32m';C_Y=$'\e[33m';C_R=$'\e[31m';C_B=$'\e[36m';C_0=$'\e[0m'
else C_G="";C_Y="";C_R="";C_B="";C_0=""; fi
REPORT="fix_secaudit_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
P=0;W=0;F=0;I=0;S=0;CHK=0
log(){ echo "$*" | tee -a "$REPORT" >/dev/null; echo "$*"; }
sect(){ log ""; log "${C_B}#################### $* ####################${C_0}"; }
chk(){ CHK=$((CHK+1)); printf -v _id "FIX-%02d" "$CHK"; log ""; log "${C_B}[$_id] $*${C_0}"; }
pass(){ P=$((P+1)); log "  ${C_G}PASS${C_0}  $*"; }
warn(){ W=$((W+1)); log "  ${C_Y}WARN${C_0}  $*"; }
fail(){ F=$((F+1)); log "  ${C_R}FAIL${C_0}  $*"; }
info(){ I=$((I+1)); log "  INFO  $*"; }
skip(){ S=$((S+1)); log "  SKIP  $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO=""; fi
log "FIX security audit | host=$(hostname) | $(date) | report=$REPORT"
[ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ] && log "${C_Y}(not root / no passwordless sudo — some checks limited)${C_0}"

# ---- shared discovery (used by many checks) -------------------------------
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
LOG_FILES=$(uniq_list "$LOG_FILES"); STORE_FILES=$(uniq_list "$STORE_FILES")
BINS=$(uniq_list "$BINS")
NIC_IPS=$( (ip -br addr 2>/dev/null | awk '{for(i=3;i<=NF;i++) if($i~/^[0-9]/)print $i}' | cut -d/ -f1) 2>/dev/null )
[ -z "$NIC_IPS" ] && NIC_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep .)

# ===========================================================================
sect "A. HOST & NETWORK POSITIONING"

chk "Multi-homing / segment separation"
n=$(echo "$NIC_IPS" | grep -c .)
[ "$n" -ge 2 ] && warn "Host has $n IPs ($(echo $NIC_IPS|tr '\n' ' ')) — verify exchange vs internal segments are separated." \
              || pass "Single interface IP."

chk "IPv4 forwarding"
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] \
  && fail "ip_forward=1 — host may bridge exchange<->internal segments." || pass "IPv4 forwarding disabled."

chk "IPv6 forwarding"
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" = "1" ] \
  && warn "IPv6 forwarding enabled." || pass "IPv6 forwarding disabled/absent."

chk "Routing between segments"
if have ip; then
  gws=$(ip route 2>/dev/null | grep -c '^default')
  [ "$gws" -gt 1 ] && warn "$gws default routes — policy routing between segments; review ip rule." || pass "Single default route."
else skip "ip not available."; fi

chk "Reverse-path / anti-spoof filter"
rp=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null)
{ [ "$rp" = "1" ] || [ "$rp" = "2" ]; } && pass "rp_filter=$rp." || warn "rp_filter=$rp — anti-spoof weak."

chk "Egress to the public internet (exfil path)"
if [ "$NO_EGRESS" = "1" ]; then skip "Egress test disabled by NO_EGRESS=1."
elif have curl; then
  code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null)
  { [ -n "$code" ] && [ "$code" != "000" ]; } && fail "Reached the internet (HTTP $code) — a trading host should have no direct egress." \
                                              || pass "No direct internet egress (request blocked/timed out)."
else skip "curl not available."; fi

chk "Exchange endpoint by hostname vs IP (DNS-MITM surface)"
if [ -n "$CFG_FILES" ]; then
  hosts=$($SUDO grep -aiEh 'SocketConnectHost|ConnectHost' $CFG_FILES 2>/dev/null | grep -aoiE '=[ ]*[a-z0-9._-]+' | grep -aiE '[a-z]{2,}' | head -5)
  if echo "$hosts" | grep -qiE '[a-z]{2,}'; then warn "Config references hostname(s) for connect — DNS spoofing becomes a MITM vector. Prefer pinned IPs."
  else pass "Endpoints appear to be IPs (no DNS dependency)."; fi
else skip "No config files found."; fi

# ===========================================================================
sect "B. FIX PROCESS & BINARY"

chk "FIX process discovery"
[ -n "$FIX_PIDS" ] && info "PIDs: $(echo $FIX_PIDS|tr '\n' ' ')" || warn "No processes matched '$FIX_PROC_PATTERN' — set FIX_PROC_PATTERN."

chk "FIX processes not running as root"
if [ -n "$FIX_PIDS" ]; then
  for pid in $FIX_PIDS; do u=$(ps -o user= -p "$pid" 2>/dev/null|tr -d ' ')
    [ "$u" = "root" ] && fail "pid=$pid runs as ROOT." || pass "pid=$pid user='$u' (non-root)."; done
else skip "No FIX PIDs."; fi

chk "Shared service account across components"
if [ -n "$FIX_PIDS" ]; then
  users=$(for pid in $FIX_PIDS; do ps -o user= -p "$pid" 2>/dev/null|tr -d ' '; done | sort -u)
  [ "$(echo "$users"|grep -c .)" -eq 1 ] && warn "All FIX components share account '$users' — compromise = full stack; consider per-role accounts." \
                                          || pass "Components use distinct accounts."
else skip "No FIX PIDs."; fi

chk "Process umask"
if [ -n "$FIX_PIDS" ]; then
  for pid in $FIX_PIDS; do um=$($SUDO grep -a Umask /proc/$pid/status 2>/dev/null|awk '{print $2}')
    [ -n "$um" ] && { { [ "$um" = "0077" ]||[ "$um" = "0027" ]; } && pass "pid=$pid umask=$um." || warn "pid=$pid umask=$um (may create group/other-readable files)."; }; done
else skip "No FIX PIDs."; fi

chk "Binary hardening (PIE/NX/canary/RELRO)"
if [ -n "$BINS" ]; then
  for b in $BINS; do [ -e "$b" ] || continue
    if have checksec; then checksec --file="$b" 2>/dev/null | tail -1 | sed 's/^/    /' | tee -a "$REPORT"; info "checksec reported for $b."
    elif have readelf; then
      nx=$($SUDO readelf -l "$b" 2>/dev/null|grep -c 'GNU_STACK.*RWE'); pie=$($SUDO readelf -h "$b" 2>/dev/null|grep -c 'DYN')
      [ "$nx" -eq 0 ] && pass "$b: NX stack." || fail "$b: executable stack (no NX)."
      [ "$pie" -gt 0 ] && pass "$b: PIE." || warn "$b: no PIE."
    else skip "no checksec/readelf."; fi; done
else skip "No binaries resolved."; fi

chk "Linked TLS library (CVE surface)"
if [ -n "$BINS" ] && have ldd; then
  for b in $BINS; do lib=$($SUDO ldd "$b" 2>/dev/null|grep -iE 'libssl|libcrypto|libgnutls'|awk '{print $3}'|sort -u|head -2)
    [ -n "$lib" ] && for l in $lib; do v=$(strings "$l" 2>/dev/null|grep -m1 -iE 'OpenSSL [0-9]|GnuTLS [0-9]'); info "$b -> $l ${v:+($v)} — check against CVEs."; done; done
else skip "ldd/binary unavailable."; fi

chk "FIX engine / version identification"
if [ -n "$BINS" ]; then
  for b in $BINS; do v=$(strings "$b" 2>/dev/null|grep -im1 -E 'quickfix|onixs|b2bits|cameronfix|fixengine|version [0-9]')
    [ -n "$v" ] && info "$b: '$v' — look up known CVEs for this engine/version." || skip "no version string in $b."; done
else skip "No binaries."; fi

# ===========================================================================
sect "C. SECRETS EXPOSURE"

mask(){ sed -E 's/((password|passwd|secret|apikey|api_key|token|554)([=:] *))[^ |]+/\1***REDACTED***/Ig'; }
scan(){ $SUDO grep -aInEi 'password|passwd|secret|apikey|api_key|token|BEGIN [A-Z ]*PRIVATE KEY|(^|\|)554=' "$1" 2>/dev/null | mask | head -3; }

chk "Cleartext secrets in configs"
h=0; for f in $CFG_FILES; do o=$(scan "$f"); [ -n "$o" ] && { h=1; fail "secret-like data in $f:"; echo "$o"|sed 's/^/        /'|tee -a "$REPORT"; }; done
[ "$h" -eq 0 ] && { [ -n "$CFG_FILES" ] && pass "No cleartext secrets in configs." || skip "No configs."; }

chk "Cleartext secrets in logs"
h=0; for f in $LOG_FILES; do o=$(scan "$f"); [ -n "$o" ] && { h=1; fail "secret-like data in log $f (masked)."; }; done
[ "$h" -eq 0 ] && { [ -n "$LOG_FILES" ] && pass "No cleartext secrets in logs (incl. tag 554)." || skip "No logs."; }

chk "Secrets in process environment"
if [ -n "$FIX_PIDS" ]; then
  h=0; for pid in $FIX_PIDS; do e=$($SUDO tr '\0' '\n' </proc/$pid/environ 2>/dev/null|grep -iE 'pass|secret|token|key='); [ -n "$e" ] && { h=1; fail "pid=$pid has secret-like env vars (masked)."; }; done
  [ "$h" -eq 0 ] && pass "No secret-like environment variables."
else skip "No FIX PIDs."; fi

chk "Secrets in shell history"
hh=0; for f in /home/*/.bash_history /root/.bash_history "$HOME/.bash_history"; do [ -r "$f" ] || continue
  $SUDO grep -aiE 'password|passwd|-p .+|secret' "$f" >/dev/null 2>&1 && { hh=1; warn "credential-like commands in $f."; }; done
[ "$hh" -eq 0 ] && pass "No obvious credentials in shell history."

chk "Core dumps present on disk (memory leak)"
cds=$($SUDO find / -maxdepth 4 -name 'core*' -type f 2>/dev/null|head -5)
[ -n "$cds" ] && warn "Core files found (may contain keys/orders): $(echo $cds|tr '\n' ' ')" || pass "No core dumps found."

chk "Core dumps disabled (ulimit)"
[ "$(ulimit -c)" = "0" ] && pass "ulimit -c 0." || warn "Core dumps enabled ($(ulimit -c))."

# ===========================================================================
sect "D. FILE PERMISSIONS"

chk "Private key / cert permissions"
if [ -n "$KEY_FILES" ]; then
  for f in $KEY_FILES; do [ -e "$f" ] || continue
    case "$f" in *.key|*.pem|*.p12|*.pfx|*.jks)
      [ -n "$($SUDO find "$f" -perm /077 2>/dev/null)" ] && fail "$f readable/accessible by group/other ($( $SUDO stat -c '%a %U' "$f" ))." \
                                                          || pass "$f locked to owner ($( $SUDO stat -c '%a %U' "$f" ))." ;;
    *) info "cert $f ($( $SUDO stat -c '%a %U' "$f" )).";; esac; done
else warn "No key files found — confirm TLS is actually used."; fi

chk "Config file permissions"
if [ -n "$CFG_FILES" ]; then
  for f in $CFG_FILES; do [ -n "$($SUDO find "$f" -perm /022 2>/dev/null)" ] && warn "$f group/other-writable." || pass "$f not world/group-writable."; done
else skip "No configs."; fi

chk "Sequence / message store permissions (replay & tamper)"
if [ -n "$STORE_FILES" ]; then
  for f in $STORE_FILES; do [ -e "$f" ] || continue
    if [ -n "$($SUDO find "$f" -perm /022 2>/dev/null)" ]; then fail "$f writable by group/other — enables sequence tamper/replay."
    elif [ -n "$($SUDO find "$f" -perm /044 2>/dev/null)" ]; then warn "$f readable by group/other — order history exposure."
    else pass "$f locked to owner."; fi; done
else warn "No message/seqnum store located — verify persistence & its permissions."; fi

chk "World-writable files in install dirs"
if [ -n "$EXTRA_DIRS" ]; then
  ww=$($SUDO find $EXTRA_DIRS -type f -perm -002 2>/dev/null|head -5)
  [ -n "$ww" ] && fail "World-writable files: $(echo $ww|tr '\n' ' ')" || pass "No world-writable files in install dirs."
else skip "Set EXTRA_DIRS to scan install tree."; fi

chk "SUID/SGID binaries in install dirs"
if [ -n "$EXTRA_DIRS" ]; then
  sgb=$($SUDO find $EXTRA_DIRS -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null|head -5)
  [ -n "$sgb" ] && warn "SUID/SGID present: $(echo $sgb|tr '\n' ' ')" || pass "No SUID/SGID in install dirs."
else skip "Set EXTRA_DIRS."; fi

# ===========================================================================
sect "E. TLS & FIX CONFIG SEMANTICS"

cfg_grep(){ [ -n "$CFG_FILES" ] || return 1; $SUDO grep -aiEh "$1" $CFG_FILES 2>/dev/null; }

chk "TLS/SSL enabled in engine config"
if [ -n "$CFG_FILES" ]; then
  cfg_grep 'SocketUseSSL *= *Y|SSLEnable *= *Y|SSLProtocol|CertificateFile|SocketPrivateKey' >/dev/null \
    && pass "TLS settings present." || warn "No TLS settings found — confirm encryption is really in use."
else skip "No configs."; fi

chk "TLS not explicitly disabled"
cfg_grep 'SocketUseSSL *= *N|SSLEnable *= *N' >/dev/null && fail "TLS explicitly disabled (SocketUseSSL=N) — plaintext FIX." || pass "TLS not disabled in config."

chk "Certificate validation not disabled"
cfg_grep 'SSLValidateCertificates *= *N|SSLVerifyClient *= *none|VerifyMode *= *0' >/dev/null && fail "Cert validation disabled — MITM risk." || pass "No 'validation-off' flags found."

chk "EncryptMethod / plaintext posture"
em=$(cfg_grep 'EncryptMethod'); if echo "$em"|grep -qE '= *0'; then
  cfg_grep 'SocketUseSSL *= *Y' >/dev/null && pass "EncryptMethod=0 but TLS at transport (expected)." || warn "EncryptMethod=0 and no TLS confirmed — messages may be plaintext."
else { [ -n "$em" ] && info "EncryptMethod: $em" || skip "EncryptMethod not set."; }; fi

chk "Weak TLS protocol pinned in config"
cfg_grep 'SSLProtocol.*(SSLv3|TLSv1\.1|TLSv1[^.])' >/dev/null && fail "Deprecated TLS protocol referenced in config." || pass "No deprecated TLS protocol pinned."

chk "Referenced cert/key files exist"
miss=0; for f in $(cfg_grep 'CertificateFile|SocketPrivateKey|SSLCACert' | grep -aoE '/[^ ]+'); do [ -e "$f" ] || { miss=1; warn "Referenced file missing: $f"; }; done
[ "$miss" -eq 0 ] && pass "Referenced cert/key files present (or none referenced)."

chk "Message-validation switches"
if cfg_grep 'ValidateFieldsOutOfOrder *= *N|ValidateUserDefinedFields *= *N|ValidateFieldsHaveValues *= *N' >/dev/null; then
  fail "One or more FIX validation checks disabled — parser accepts malformed input."; else pass "No validation switches disabled."; fi

chk "HeartBtInt sanity"
hb=$(cfg_grep 'HeartBtInt' | grep -aoE '[0-9]+' | head -1)
[ -n "$hb" ] && { { [ "$hb" -gt 60 ] 2>/dev/null; } && warn "HeartBtInt=$hb s — slow to detect dead/hijacked session." || pass "HeartBtInt=$hb s."; } || skip "HeartBtInt not set."

chk "Reset-on-logon/logout policy"
cfg_grep 'ResetOnLogon *= *Y|ResetOnLogout *= *Y|ResetOnDisconnect *= *Y' >/dev/null && info "Sequence reset-on-* enabled — verify it matches exchange spec (affects replay/gap handling)." || pass "No aggressive reset-on-* flags."

chk "Session schedule (off-hours connect window)"
sch=$(cfg_grep 'StartTime|EndTime'); [ -n "$sch" ] && info "Session schedule configured: $(echo $sch|tr '\n' ' ')" || warn "No StartTime/EndTime — session may connect 24x7."

# ===========================================================================
sect "F. NETWORK EXPOSURE"

chk "FIX ports bound to 0.0.0.0"
if have ss; then
  for p in $FIX_PORTS; do l=$($SUDO ss -tlnp 2>/dev/null|awk -v x=":$p\$" '$4~x'); [ -z "$l" ] && continue
    echo "$l"|grep -qE '(0\.0\.0\.0|\*):'"$p" && warn "port $p bound to all interfaces — bind to a specific IP." || pass "port $p bound to specific address."; done
else skip "ss unavailable."; fi

chk "Full TCP listener inventory"
if have ss; then $SUDO ss -tlnp 2>/dev/null | tee -a "$REPORT" >/dev/null; info "Listener inventory written to report — review for unexpected services."; else skip "ss unavailable."; fi

chk "Passive cleartext-FIX detection (observe-only)"
if [ "$DO_CAPTURE" = "1" ] && [ -n "$CAPTURE" ] && have tcpdump; then
  CH=${CAPTURE%:*}; CP=${CAPTURE##*:}
  d=$($SUDO timeout 15 tcpdump -i any -A -s0 -c 40 "host $CH and port $CP" 2>/dev/null)
  echo "$d"|grep -aqE '8=FIXT?\.[0-9]' && fail "CLEARTEXT FIX on $CH:$CP." || { [ -n "$d" ] && pass "No cleartext FIX on $CH:$CP (likely TLS)." || info "no packets captured."; }
else skip "Enable with CAPTURE=IP:PORT ... -c (use an IN-SCOPE session, not an exchange port)."; fi

chk "TLS scan of own listeners (active, own IPs only)"
if [ "$DO_TLS_SCAN" = "1" ]; then
  for ip in $NIC_IPS; do for p in $FIX_PORTS; do
    $SUDO ss -tlnp 2>/dev/null|awk -v a="$ip:$p" '$4==a{f=1}END{exit !f}' || continue
    if have testssl.sh; then testssl.sh --quiet --protocols "$ip:$p" 2>/dev/null|tee -a "$REPORT"; info "testssl $ip:$p done."
    elif have nmap; then nmap --script ssl-enum-ciphers -p "$p" "$ip" 2>/dev/null|tee -a "$REPORT"; info "nmap ssl-enum $ip:$p done."
    else skip "no testssl/nmap."; fi; done; done
else skip "Enable with -t (scans YOUR listeners only, never exchange ports)."; fi

# ===========================================================================
sect "G. HOST HARDENING"

chk "systemd sandbox exposure"
if have systemd-analyze && [ -n "$FIX_PIDS" ]; then
  for pid in $FIX_PIDS; do u=$(grep -aoE '[a-zA-Z0-9_.@-]+\.service' /proc/$pid/cgroup 2>/dev/null|head -1)
    [ -n "$u" ] && { sc=$(systemd-analyze security "$u" 2>/dev/null|grep -i 'Overall exposure'|awk '{print $NF}'); info "$u exposure=$sc (lower better; <5 good)."; }; done
else skip "systemd-analyze unavailable / no unit."; fi

chk "Mandatory access control (SELinux/AppArmor)"
if have getenforce; then [ "$(getenforce)" = "Enforcing" ] && pass "SELinux Enforcing." || warn "SELinux $(getenforce)."
elif have aa-status; then $SUDO aa-status >/dev/null 2>&1 && pass "AppArmor active." || warn "AppArmor not confirmed."
else warn "No MAC tooling found."; fi

chk "Firewall egress policy"
if have nft && $SUDO nft list ruleset >/dev/null 2>&1; then
  [ "$($SUDO nft list ruleset 2>/dev/null|grep -c .)" -gt 0 ] && pass "nftables ruleset present — verify default-deny egress." || warn "nftables empty."
elif have iptables; then [ "$($SUDO iptables -S 2>/dev/null|grep -c .)" -gt 3 ] && pass "iptables rules present." || warn "iptables largely empty — egress likely open."
else warn "No firewall tooling."; fi

chk "SSH hardening"
scf=/etc/ssh/sshd_config
if [ -r "$scf" ]; then
  $SUDO grep -qiE '^\s*PermitRootLogin\s+(yes|prohibit-password)' "$scf" && warn "PermitRootLogin not fully disabled." || pass "Root SSH login restricted."
  $SUDO grep -qiE '^\s*PasswordAuthentication\s+no' "$scf" && pass "SSH password auth disabled." || warn "SSH password auth enabled."
else skip "sshd_config unreadable."; fi

chk "Time synchronization (NTP)"
if have timedatectl; then timedatectl show -p NTPSynchronized --value 2>/dev/null|grep -qi yes && pass "Clock NTP-synced." || warn "Clock NOT synced — FIX timestamps/audit at risk."
elif have chronyc; then chronyc tracking 2>/dev/null|grep -i 'Leap status'|grep -qi Normal && pass "chrony synced." || warn "chrony sync uncertain."
else warn "No NTP tooling."; fi

chk "Pending security updates"
if have apt-get; then u=$(apt-get -s upgrade 2>/dev/null|grep -c '^Inst.*ecurit'); [ "$u" -gt 0 ] && warn "$u security updates pending." || pass "No pending security updates (apt)."
elif have yum; then u=$(yum -q check-update --security 2>/dev/null|grep -c '.'); [ "$u" -gt 0 ] && warn "security updates pending (yum)." || pass "No pending security updates (yum)."
else skip "No package manager detected."; fi

chk "Kernel currency / uptime"
info "kernel=$(uname -r) uptime=$(uptime -p 2>/dev/null || cut -d. -f1 /proc/uptime)s — long uptime may mean missed kernel patches."

# ===========================================================================
sect "H. PRIVILEGE ESCALATION & LATERAL MOVEMENT"

chk "Service-account sudo rights"
sr=$($SUDO -l 2>/dev/null | grep -cE 'ALL|NOPASSWD')
[ "$sr" -gt 0 ] && warn "Current/service account has sudo rights (ALL/NOPASSWD present) — escalation path from a compromised FIX process." || pass "No broad sudo rights detected."

chk "SSH trust (authorized_keys / known_hosts)"
ak=0; for f in /home/*/.ssh/authorized_keys "$HOME/.ssh/authorized_keys"; do [ -r "$f" ] || continue
  c=$($SUDO grep -c . "$f" 2>/dev/null); [ "$c" -gt 0 ] && { ak=1; warn "$f has $c trusted key(s) — map lateral access."; }; done
[ "$ak" -eq 0 ] && pass "No readable authorized_keys with entries."

chk "Cron jobs / systemd timers"
cj=$($SUDO ls /etc/cron.d /etc/cron.daily 2>/dev/null|grep -c .); tm=$(systemctl list-timers --no-legend 2>/dev/null|grep -c .)
info "cron entries=$cj, systemd timers=$tm — review any that touch FIX configs/keys/logs or deployment."

chk "Writable directories in PATH"
wp=0; for d in $(echo "$PATH"|tr ':' ' '); do { [ -d "$d" ] && [ -n "$($SUDO find "$d" -maxdepth 0 -perm -002 2>/dev/null)" ]; } && { wp=1; warn "world-writable PATH dir: $d"; }; done
[ "$wp" -eq 0 ] && pass "No world-writable PATH directories."

# ===========================================================================
sect "I. AUDIT, MONITORING, INTEGRITY & DEPLOYMENT"

chk "File-integrity monitoring present"
{ have aide || have tripwire; } && pass "FIM tool present ($(command -v aide tripwire 2>/dev/null|tr '\n' ' '))." || warn "No AIDE/Tripwire — config/key tampering may go unnoticed."

chk "auditd coverage of keys/configs"
if have auditctl; then $SUDO auditctl -l 2>/dev/null | grep -qiE '\.key|\.cfg|/etc/ssh|fix' && pass "audit rules cover sensitive paths." || warn "No audit rules on FIX keys/configs."
else warn "auditd not present."; fi

chk "Remote log forwarding (off-host)"
grep -qsrE '^\*\.\*|@@?[0-9a-zA-Z]' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null && pass "rsyslog forwarding configured — logs survive host compromise." || warn "No remote log forwarding — FIX/audit logs only local."

chk "Log file permissions"
if [ -n "$LOG_FILES" ]; then
  h=0; for f in $LOG_FILES; do [ -n "$($SUDO find "$f" -perm /044 2>/dev/null)" ] && { h=1; warn "$f readable by group/other (order data exposure)."; }; done
  [ "$h" -eq 0 ] && pass "Log files not world/group-readable."
else skip "No logs discovered."; fi

chk "Deployment integrity (checksum/signature)"
if [ -n "$EXTRA_DIRS" ]; then
  man=$($SUDO find $EXTRA_DIRS -maxdepth 2 \( -iname '*.sha256*' -o -iname '*.sig' -o -iname 'SHA256SUMS' \) 2>/dev/null|head -3)
  [ -n "$man" ] && info "Integrity manifest(s): $(echo $man|tr '\n' ' ') — verify against deployed files." || warn "No checksum/signature manifest found beside deployment."
else skip "Set EXTRA_DIRS."; fi

# ===========================================================================
sect "SUMMARY"
log "Checks run: $CHK   ${C_G}PASS=$P${C_0}  ${C_Y}WARN=$W${C_0}  ${C_R}FAIL=$F${C_0}  INFO=$I  SKIP=$S"
log ""
log "Reminder: active FIX-protocol attacks (SenderCompID spoof, SequenceReset,"
log "replay, admin-message injection, fuzzing, downstream injection) are NOT in"
log "this script and must run against a SIMULATOR, never a live exchange session."
log "Full report: $REPORT"
[ "$F" -gt 0 ] && exit 2 || exit 0
