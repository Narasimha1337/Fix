#!/usr/bin/env bash
#
# fix_secaudit.sh — READ-ONLY security validation for a FIX protocol host
# ---------------------------------------------------------------------------
# Validates the defensive controls from the FIX 5.0 hardening guide against a
# live Linux server running a FIX thick client / gateway stack.
#
#  SCOPE / SAFETY (read before running):
#   * This script is NON-DESTRUCTIVE and READ-ONLY. It does not send FIX
#     messages, spoof, inject, fuzz, or otherwise attack any session.
#   * Active FIX-protocol attacks (SenderCompID spoof, SequenceReset, replay,
#     fuzzing, injection) must be run against a SIMULATOR, never a live
#     exchange session. This script does none of that.
#   * The optional passive packet check only OBSERVES bytes already on the
#     wire. The optional TLS scan targets YOUR OWN listeners only.
#   * Run only with written authorization for this host.
#
#  USAGE:
#     sudo ./fix_secaudit.sh                 # full read-only audit
#     sudo ./fix_secaudit.sh -t              # also TLS-scan own listeners
#     sudo CAPTURE="10.56.69.15:9996" \
#          sudo ./fix_secaudit.sh -c         # also passively sniff one session
#
#  Requires (degrades gracefully if missing): ss, lsof, ps, stat, grep, awk.
#  Optional: tcpdump, testssl.sh|nmap|openssl, systemd-analyze, getenforce,
#            aa-status, nft|iptables, timedatectl|chronyc, trufflehog.
# ---------------------------------------------------------------------------

# ---- CONFIG (edit for your environment) -----------------------------------
# Regex of process names that make up your FIX stack.
FIX_PROC_PATTERN="${FIX_PROC_PATTERN:-Eqt|quickfix|QuickFix|fixengine|fixgw|fix_}"
# Ports commonly used by your FIX sessions (used to spot listeners/exposure).
FIX_PORTS="${FIX_PORTS:-9090 9100 9256 9996 9997 9998 49000 49042 64403}"
# Optional passive capture target "IP:PORT" (only ONE of your sessions).
CAPTURE="${CAPTURE:-}"
# Extra directories to scan for configs/keys/logs (space separated).
EXTRA_DIRS="${EXTRA_DIRS:-}"
# ---------------------------------------------------------------------------

DO_TLS_SCAN=0
DO_CAPTURE=0
while getopts "tch" opt; do
  case "$opt" in
    t) DO_TLS_SCAN=1 ;;
    c) DO_CAPTURE=1 ;;
    h) grep '^#' "$0" | sed 's/^#//'; exit 0 ;;
    *) ;;
  esac
done

# ---- output helpers -------------------------------------------------------
if [ -t 1 ]; then C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_B=$'\e[36m'; C_0=$'\e[0m'
else C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""; fi
REPORT="fix_secaudit_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
P=0; W=0; F=0; I=0
log()  { echo "$*" | tee -a "$REPORT" >/dev/null; echo "$*"; }
sect() { log ""; log "${C_B}=== $* ===${C_0}"; }
pass() { P=$((P+1)); log "${C_G}[PASS]${C_0} $*"; }
warn() { W=$((W+1)); log "${C_Y}[WARN]${C_0} $*"; }
fail() { F=$((F+1)); log "${C_R}[FAIL]${C_0} $*"; }
info() { I=$((I+1)); log "[INFO] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# sudo helper: use sudo -n if we are not root and it is available non-interactively
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  if sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO=""; fi
fi

log "FIX security audit  |  host=$(hostname)  |  $(date)"
log "Report: $REPORT"
[ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ] && \
  warn "Not root and passwordless sudo unavailable — some checks (other users' /proc, tcpdump, keys) will be limited."

# ===========================================================================
sect "1. Host context & network positioning"
if have ip; then
  ip -br addr 2>/dev/null | tee -a "$REPORT"
  NIC_IPS=$(ip -br addr 2>/dev/null | awk '{for(i=3;i<=NF;i++) if($i ~ /^[0-9]/) print $i}' | cut -d/ -f1)
  N=$(echo "$NIC_IPS" | grep -c .)
  [ "$N" -ge 2 ] && warn "Host is multi-homed ($N IPs) — verify segment separation (exchange vs internal)." \
                 || info "Single IP detected."
else
  NIC_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep .)
fi
IPFWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$IPFWD" = "1" ]; then
  fail "net.ipv4.ip_forward=1 — host forwards between segments (possible bridge exchange<->internal)."
else
  pass "IP forwarding disabled."
fi

# ===========================================================================
sect "2. FIX process discovery & attribution"
FIX_PIDS=$(pgrep -f "$FIX_PROC_PATTERN" 2>/dev/null | sort -u)
if [ -z "$FIX_PIDS" ]; then
  warn "No processes matched pattern '$FIX_PROC_PATTERN'. Set FIX_PROC_PATTERN and rerun."
else
  for pid in $FIX_PIDS; do
    [ -d "/proc/$pid" ] || continue
    puser=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
    pcmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-100)
    pcwd=$($SUDO readlink "/proc/$pid/cwd" 2>/dev/null)
    log "  pid=$pid user=${puser:-?} cwd=${pcwd:-?}"
    log "     cmd: ${pcmd:-?}"
    if [ "$puser" = "root" ]; then
      fail "FIX process pid=$pid runs as ROOT — should be a dedicated non-root service account."
    else
      pass "pid=$pid runs as non-root user '${puser}'."
    fi
  done
fi

# Collect config/log/store/key files opened by the FIX processes.
CFG_FILES=""; KEY_FILES=""; LOG_FILES=""
if have lsof && [ -n "$FIX_PIDS" ]; then
  for pid in $FIX_PIDS; do
    OF=$($SUDO lsof -p "$pid" 2>/dev/null | awk '{print $NF}')
    CFG_FILES="$CFG_FILES $(echo "$OF" | grep -Ei '\.(cfg|ini|conf|properties|xml)$')"
    KEY_FILES="$KEY_FILES $(echo "$OF" | grep -Ei '\.(pem|key|jks|p12|pfx|crt|cer)$')"
    LOG_FILES="$LOG_FILES $(echo "$OF" | grep -Ei '\.(log|messages)|message|event')"
  done
fi
# Add extra dirs
for d in $EXTRA_DIRS; do
  [ -d "$d" ] || continue
  CFG_FILES="$CFG_FILES $($SUDO find "$d" -type f \( -name '*.cfg' -o -name '*.ini' -o -name '*.conf' -o -name '*.properties' \) 2>/dev/null)"
  KEY_FILES="$KEY_FILES $($SUDO find "$d" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.jks' -o -name '*.p12' \) 2>/dev/null)"
done
CFG_FILES=$(echo "$CFG_FILES" | tr ' ' '\n' | sort -u | grep .)
KEY_FILES=$(echo "$KEY_FILES" | tr ' ' '\n' | sort -u | grep .)
LOG_FILES=$(echo "$LOG_FILES" | tr ' ' '\n' | sort -u | grep .)
[ -n "$CFG_FILES" ] && info "Config files: $(echo "$CFG_FILES" | tr '\n' ' ')"
[ -n "$KEY_FILES" ] && info "Key/cert files: $(echo "$KEY_FILES" | tr '\n' ' ')"
[ -n "$LOG_FILES" ] && info "Log/message files: $(echo "$LOG_FILES" | tr '\n' ' ')"

# ===========================================================================
sect "3. Key & sensitive-file permissions"
if [ -z "$KEY_FILES" ]; then
  warn "No key/cert files discovered — verify TLS is actually in use."
else
  for f in $KEY_FILES; do
    [ -e "$f" ] || continue
    perm=$($SUDO stat -c '%a' "$f" 2>/dev/null)
    ownr=$($SUDO stat -c '%U' "$f" 2>/dev/null)
    case "$f" in
      *.key|*.pem|*.p12|*.pfx|*.jks)
        if [ -n "$perm" ] && [ "$perm" -gt 600 ] 2>/dev/null; then
          fail "Private key $f is $perm ($ownr) — too permissive; should be 600/400."
        else
          pass "Key $f perms=$perm owner=$ownr."
        fi ;;
      *) info "Cert $f perms=$perm owner=$ownr." ;;
    esac
  done
fi

# ===========================================================================
sect "4. Secrets exposure (configs & logs)"
scan_secrets() {  # $1=file  — reports presence, MASKS the value
  local f="$1"
  $SUDO grep -aInEi 'password|passwd|secret|apikey|api_key|BEGIN [A-Z ]*PRIVATE KEY|(^|\|)554=' "$f" 2>/dev/null \
    | sed -E 's/(password|passwd|secret|apikey|api_key|554)([=:] *)[^ |]+/\1\2***REDACTED***/Ig' \
    | head -n 5
}
SEC_HIT=0
for f in $CFG_FILES $LOG_FILES; do
  [ -e "$f" ] || continue
  out=$(scan_secrets "$f")
  if [ -n "$out" ]; then
    SEC_HIT=1
    fail "Possible cleartext secret in $f:"
    echo "$out" | sed 's/^/        /' | tee -a "$REPORT"
  fi
done
[ "$SEC_HIT" -eq 0 ] && pass "No obvious cleartext passwords/keys in discovered configs/logs."
if have trufflehog && [ -n "$EXTRA_DIRS" ]; then
  info "Running trufflehog on $EXTRA_DIRS (summary only)..."
  for d in $EXTRA_DIRS; do trufflehog filesystem "$d" --no-update 2>/dev/null | grep -c 'Found' | \
    xargs -I{} info "trufflehog potential secrets in $d: {}"; done
fi

# ===========================================================================
sect "5. TLS configuration in FIX engine"
if [ -z "$CFG_FILES" ]; then
  warn "No config files to inspect for TLS settings."
else
  TLS_OK=0
  for f in $CFG_FILES; do
    if $SUDO grep -aInEi 'SocketUseSSL *= *Y|SSLEnable *= *Y|SSLProtocol|CertificateFile|SocketPrivateKey|SSLServerName|TransportDataDictionary.*SSL' "$f" >/dev/null 2>&1; then
      TLS_OK=1
      $SUDO grep -aInEi 'SocketUseSSL|SSLProtocol|Certificate|SSLValidate|SSLCACert' "$f" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
    fi
    if $SUDO grep -aInEi 'SocketUseSSL *= *N|SSLEnable *= *N' "$f" >/dev/null 2>&1; then
      fail "TLS explicitly DISABLED in $f (SocketUseSSL=N) — FIX would be plaintext."
    fi
    # Cert validation often defaults OFF in engines
    if $SUDO grep -aInEi 'SSLValidateCertificates *= *N|SSLVerifyClient *= *none' "$f" >/dev/null 2>&1; then
      fail "Certificate validation appears DISABLED in $f — MITM risk."
    fi
  done
  [ "$TLS_OK" -eq 1 ] && pass "TLS/SSL configuration present in FIX config (verify cert validation is enforced)." \
                      || warn "No TLS/SSL settings found in configs — confirm encryption is really in use."
fi

# ===========================================================================
sect "6. Network exposure (listeners / binds)"
if have ss; then
  $SUDO ss -tlnp 2>/dev/null | tee -a "$REPORT" >/dev/null
  for port in $FIX_PORTS; do
    line=$($SUDO ss -tlnp 2>/dev/null | awk -v p=":$port$" '$4 ~ p')
    [ -z "$line" ] && continue
    if echo "$line" | grep -q '0\.0\.0\.0:'"$port"'\|\*:'"$port"; then
      warn "FIX port $port bound to 0.0.0.0 (all interfaces) — exposed on every segment; bind to a specific IP."
    else
      pass "FIX port $port bound to a specific address."
    fi
  done
else
  warn "ss not available — cannot enumerate listeners."
fi

# ===========================================================================
sect "7. Host hardening"
# systemd sandbox score per FIX unit
if have systemd-analyze && [ -n "$FIX_PIDS" ]; then
  for pid in $FIX_PIDS; do
    unit=$(cat "/proc/$pid/cgroup" 2>/dev/null | grep -oE '[a-zA-Z0-9_.@-]+\.service' | head -n1)
    if [ -n "$unit" ]; then
      score=$(systemd-analyze security "$unit" 2>/dev/null | grep -iE 'Overall exposure' | awk '{print $NF}')
      [ -n "$score" ] && info "systemd exposure for $unit: $score (lower is better; <5 good)."
    fi
  done
else
  info "systemd-analyze not available or no units resolved — check sandboxing manually."
fi
# MAC
if have getenforce; then
  m=$(getenforce 2>/dev/null); [ "$m" = "Enforcing" ] && pass "SELinux Enforcing." || warn "SELinux: $m."
elif have aa-status; then
  $SUDO aa-status >/dev/null 2>&1 && pass "AppArmor active." || warn "AppArmor not confirmed."
else
  warn "No SELinux/AppArmor tooling found — MAC status unknown."
fi
# Firewall / egress
if have nft && $SUDO nft list ruleset >/dev/null 2>&1; then
  rules=$($SUDO nft list ruleset 2>/dev/null | grep -c .)
  [ "$rules" -gt 0 ] && pass "nftables ruleset present ($rules lines) — verify default-deny egress." \
                     || warn "nftables present but empty."
elif have iptables; then
  ir=$($SUDO iptables -S 2>/dev/null | grep -c .)
  [ "$ir" -gt 3 ] && pass "iptables rules present — verify egress allow-list to exchange+downstream." \
                  || warn "iptables largely empty — egress likely unrestricted."
else
  warn "No firewall tooling found."
fi
# core dumps
cd=$(ulimit -c)
[ "$cd" = "0" ] && pass "Core dumps disabled (ulimit -c 0)." || warn "Core dumps enabled ($cd) — may leak secrets from memory."

# ===========================================================================
sect "8. Time synchronization"
if have timedatectl; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
    pass "Clock NTP-synchronized."
  else
    warn "Clock NOT synchronized — FIX timestamps/sequencing and audit reliability at risk."
  fi
elif have chronyc; then
  chronyc tracking 2>/dev/null | grep -i 'Leap status' | grep -qi Normal \
    && pass "chrony reports normal sync." || warn "chrony sync uncertain."
else
  warn "No NTP tooling detected."
fi

# ===========================================================================
sect "9. Passive wire check (cleartext FIX detection)  [observe-only]"
if [ "$DO_CAPTURE" -eq 1 ] && [ -n "$CAPTURE" ]; then
  CH=${CAPTURE%:*}; CP=${CAPTURE##*:}
  if have tcpdump; then
    info "Sniffing up to 40 packets on $CH:$CP for ~15s (passive)..."
    dump=$($SUDO timeout 15 tcpdump -i any -A -s0 -c 40 "host $CH and port $CP" 2>/dev/null)
    if echo "$dump" | grep -aqE '8=FIXT?\.[0-9]'; then
      fail "CLEARTEXT FIX detected on $CH:$CP (found '8=FIX...') — session is unencrypted."
    elif [ -n "$dump" ]; then
      pass "Traffic on $CH:$CP does not look like cleartext FIX (likely TLS/encrypted)."
    else
      info "No packets captured (session idle or filtered)."
    fi
  else
    warn "tcpdump not available — cannot run passive capture."
  fi
else
  info "Passive capture skipped. Enable with: CAPTURE=\"IP:PORT\" ./fix_secaudit.sh -c  (use ONE of YOUR sessions)."
fi

# ===========================================================================
sect "10. TLS scan of OWN listeners  [active — own IPs only]"
if [ "$DO_TLS_SCAN" -eq 1 ]; then
  for ip in $NIC_IPS; do
    for port in $FIX_PORTS; do
      $SUDO ss -tlnp 2>/dev/null | awk -v a="$ip:$port" '$4==a{f=1} END{exit !f}' || continue
      log "  -- scanning own listener $ip:$port --"
      if have testssl.sh; then testssl.sh --quiet --protocols "$ip:$port" 2>/dev/null | tee -a "$REPORT"
      elif have nmap; then nmap --script ssl-enum-ciphers -p "$port" "$ip" 2>/dev/null | tee -a "$REPORT"
      elif have openssl; then
        for proto in tls1 tls1_1; do
          if echo | openssl s_client -connect "$ip:$port" -"$proto" 2>/dev/null | grep -q 'Cipher.*[A-Z]'; then
            fail "$ip:$port accepts deprecated $proto."
          fi
        done
        pass "openssl legacy-protocol probe complete for $ip:$port."
      fi
    done
  done
else
  info "TLS scan skipped. Enable with -t (scans YOUR listeners only, never exchange ports)."
fi

# ===========================================================================
sect "Summary"
log "PASS=$P  WARN=$W  FAIL=$F  INFO=$I"
log ""
log "Reminder: active FIX-protocol attacks (SenderCompID spoof, SequenceReset,"
log "replay, admin-message injection, fuzzing, downstream injection) are NOT"
log "part of this script and must be executed against a SIMULATOR, never a live"
log "exchange session. Full report saved to: $REPORT"
[ "$F" -gt 0 ] && exit 2 || exit 0

