#!/bin/bash
# Emergency recovery: restore networking after a botched TUN test on macOS.
#
# Run with sudo. Safe to run when nothing is wrong — every command is
# idempotent / failure-tolerant. No reboot required.
#
# What this does:
#   1. Kills the privileged launcher script (sticky after Ctrl+C on older builds).
#   2. Kills tun2socks.
#   3. Removes the split-default routes we install (0.0.0.0/1 + 128.0.0.0/1
#      and ::/1 + 8000::/1).
#   4. Removes any lingering /32 or /128 bypass routes pointing at utun100..120.
#   5. Brings down nexray-managed utun devices.
#   6. Wipes per-session state files in $TMPDIR.
#
# Usage:
#   sudo ./scripts/tun-recover.sh

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

echo "=== nexray TUN recovery ==="

# 1. Kill leftover privileged processes.
pkill -f nexray-tun-launcher 2>/dev/null && echo "killed nexray-tun-launcher" || true
pkill -x tun2socks 2>/dev/null && echo "killed tun2socks" || true

# 2. Tear down split-default routes regardless of which utun was used.
# `route delete -net 0.0.0.0/1` matches by destination prefix — it doesn't
# matter what interface it pointed to, the kernel finds the route.
for r in "0.0.0.0/1" "128.0.0.0/1"; do
  if route -n delete -net "$r" 2>/dev/null; then
    echo "deleted route -net $r"
  fi
done
for r in "::/1" "8000::/1"; do
  if route -n delete -inet6 -net "$r" 2>/dev/null; then
    echo "deleted route -inet6 -net $r"
  fi
done

# 3. Bring down nexray utun devices (utun100..120 — we iterate from
#    utun100 in the launcher and may go up to +20).
for n in $(seq 100 120); do
  if ifconfig "utun$n" >/dev/null 2>&1; then
    ifconfig "utun$n" down 2>/dev/null && echo "ifconfig utun$n down" || true
  fi
done

# 4. Remove per-session bypass routes by scanning the routing table for
#    anything still pointing at our utun devices.
netstat -rn | awk -v RS='\n' '
  $NF ~ /^utun(1[0-9]{2})$/ && $1 != "default" {
    print $1, $NF
  }
' | while read -r dest iface; do
  # Treat IPv6 by checking for ":" in the destination.
  if [[ "$dest" == *:* ]]; then
    route -n delete -inet6 "$dest" 2>/dev/null && echo "deleted -inet6 $dest" || true
  else
    route -n delete "$dest" 2>/dev/null && echo "deleted $dest" || true
  fi
done

# 5. Clear per-session temp state. TMPDIR may belong to whoever invoked
#    sudo (the SUDO_USER's TMPDIR is what nexray writes to), so check the
#    invoking user's tempdir first, then fall back to /tmp.
target_tmp=""
if [ -n "${SUDO_USER:-}" ]; then
  user_tmp=$(sudo -u "$SUDO_USER" /usr/bin/env -- bash -c 'echo "$TMPDIR"' 2>/dev/null)
  if [ -n "$user_tmp" ] && [ -d "$user_tmp" ]; then
    target_tmp="$user_tmp"
  fi
fi
if [ -z "$target_tmp" ]; then
  target_tmp="${TMPDIR:-/tmp}"
fi
removed_count=0
for f in "$target_tmp"/nexray-tun-*; do
  [ -e "$f" ] || continue
  rm -f "$f" && removed_count=$((removed_count + 1))
done
if [ "$removed_count" -gt 0 ]; then
  echo "removed $removed_count temp file(s) from $target_tmp"
fi

echo
echo "=== state after recovery ==="
echo "default route v4: $(route -n get default 2>/dev/null | awk '/gateway:/{print $2}' || echo none)"
echo "default route v6: $(route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2}' || echo none)"
echo "utun devices still up:"
ifconfig 2>/dev/null | awk '/^utun[0-9]+:/ && /UP/{print "  " $1}' | head
echo "leftover nexray procs:"
pgrep -lf 'nexray-tun-launcher|tun2socks' 2>/dev/null | sed 's/^/  /' || echo "  (none)"
echo
echo "Test connectivity:  curl -m 5 https://ifconfig.me"
