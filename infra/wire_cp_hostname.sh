#!/usr/bin/env bash
# Wire the control plane to a public hostname with Caddy + HTTPS.
#
# Intended to run ON the CP VM as root. No interactive prompts.
#
#   sudo TOOLPAIN_HOSTNAME=toolpain.com bash infra/wire_cp_hostname.sh
#
# Behavior:
# - If DNS for $TOOLPAIN_HOSTNAME already resolves to this VM's public IPv4,
#   install/configure Caddy, open 80/443, set CONTROL_PLANE_URL=https://$host,
#   restart services, and verify HTTPS health.
# - If DNS does not match yet, exit 0 with a clear "waiting for DNS" message
#   (so deploy agents can retry later without failing the whole install).
# - Never asks a human to paste instructions mid-deploy.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root on the control-plane VM" >&2
  exit 1
fi

HOSTNAME_FQDN="${TOOLPAIN_HOSTNAME:-toolpain.com}"
ROOT="${TOOLPAIN_ROOT:-/opt/toolpain}"
ENV_FILE="${TOOLPAIN_ENV:-$ROOT/.env}"
CADDYFILE_SRC="${TOOLPAIN_CADDYFILE:-$ROOT/Caddyfile}"
export DEBIAN_FRONTEND=noninteractive

public_ip() {
  # Prefer Vultr metadata; fall back to common helpers.
  curl -fsS --max-time 3 http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null \
    || curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
    || curl -fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null \
    || true
}

dns_a_records() {
  local host="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short "$host" A | grep -E '^[0-9.]+$' || true
  else
    getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u || true
  fi
}

SELF_IP="$(public_ip | tr -d '[:space:]')"
if [[ -z "$SELF_IP" ]]; then
  echo "error: could not determine this VM's public IPv4" >&2
  exit 1
fi

RESOLVED="$(dns_a_records "$HOSTNAME_FQDN" | tr '\n' ' ')"
echo "wire_cp_hostname host=$HOSTNAME_FQDN self_ip=$SELF_IP dns=[$RESOLVED]"

MATCH=0
for ip in $RESOLVED; do
  if [[ "$ip" == "$SELF_IP" ]]; then
    MATCH=1
    break
  fi
done

if [[ "$MATCH" -ne 1 ]]; then
  cat <<EOF
waiting_for_dns: $HOSTNAME_FQDN does not resolve to $SELF_IP yet.
Point an A record at $SELF_IP, then re-run:
  sudo TOOLPAIN_HOSTNAME=$HOSTNAME_FQDN bash $ROOT/infra/wire_cp_hostname.sh
EOF
  exit 0
fi

# --- DNS matches: finish HTTPS wiring without further human steps ---
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

if ! command -v caddy >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y --no-install-recommends debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -y
  apt-get install -y caddy
fi

if [[ -f "$CADDYFILE_SRC" ]]; then
  # Keep checked-in www redirect when hostname is toolpain.com; otherwise generate both sites.
  if [[ "$HOSTNAME_FQDN" == "toolpain.com" ]]; then
    cp "$CADDYFILE_SRC" /etc/caddy/Caddyfile
  else
    cat >/etc/caddy/Caddyfile <<EOF
$HOSTNAME_FQDN {
	encode gzip
	reverse_proxy 127.0.0.1:8000
}
www.${HOSTNAME_FQDN} {
	redir https://${HOSTNAME_FQDN}{uri} permanent
}
EOF
  fi
else
  cat >/etc/caddy/Caddyfile <<EOF
$HOSTNAME_FQDN {
	encode gzip
	reverse_proxy 127.0.0.1:8000
}
www.${HOSTNAME_FQDN} {
	redir https://${HOSTNAME_FQDN}{uri} permanent
}
EOF
fi
# Verify both hostnames when possible (non-fatal if www missing)
curl -fsS --max-time 15 "https://${HOSTNAME_FQDN}/api/health" >/dev/null || true

URL="https://${HOSTNAME_FQDN}"
if [[ -f "$ENV_FILE" ]]; then
  tmp="$(mktemp)"
  awk -v u="$URL" '
    BEGIN { done=0 }
    /^CONTROL_PLANE_URL=/ { print "CONTROL_PLANE_URL=" u; done=1; next }
    { print }
    END { if (!done) print "CONTROL_PLANE_URL=" u }
  ' "$ENV_FILE" >"$tmp"
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

systemctl enable --now caddy
systemctl reload caddy || systemctl restart caddy
systemctl restart toolpain 2>/dev/null || true

# Wait for ACME + uvicorn
ok=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 10 "$URL/api/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 5
done

if [[ "$ok" -ne 1 ]]; then
  echo "error: $URL/api/health not healthy after wiring" >&2
  journalctl -u caddy -n 30 --no-pager >&2 || true
  exit 1
fi

echo "wired_ok CONTROL_PLANE_URL=$URL"
curl -fsS --max-time 10 "$URL/api/health"; echo
