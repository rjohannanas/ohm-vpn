#!/usr/bin/env bash
# StealthVPN — Server Setup Script
# Tested on Ubuntu 22.04 LTS
# Run as root: sudo bash setup.sh YOUR_DOMAIN [EMAIL]

set -euo pipefail

DOMAIN="${1:?Usage: $0 <your-domain> [admin-email]}"
EMAIL="${2:-"admin@${DOMAIN}"}"

VPN_USER="stealthvpn"
BINARY_PATH="/usr/local/bin/stealthvpn-server"
SERVICE_PATH="/etc/systemd/system/stealthvpn.service"
NGINX_CONF="/etc/nginx/sites-available/stealthvpn"
DECOY_ROOT="/var/www/stealthvpn-decoy"
LOG_DIR="/var/log/stealthvpn"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== StealthVPN Server Setup for domain: $DOMAIN ==="

# ── 1. System dependencies ────────────────────────────────────────────────────
echo "[1/9] Installing system dependencies..."
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx ufw curl

# ── 2. Firewall ───────────────────────────────────────────────────────────────
echo "[2/9] Configuring firewall..."
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "HTTP (ACME challenge)"
ufw allow 443/tcp  comment "HTTPS / VPN"
ufw --force enable

# ── 3. IP forwarding (required for VPN routing) ───────────────────────────────
echo "[3/9] Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    sed -i 's/#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
fi
sysctl -p

# ── 4. Dedicated system user ──────────────────────────────────────────────────
echo "[4/9] Creating system user '$VPN_USER'..."
if ! id "$VPN_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$VPN_USER"
fi

mkdir -p "$LOG_DIR"
chown "$VPN_USER:$VPN_USER" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# ── 5. Decoy website ──────────────────────────────────────────────────────────
echo "[5/9] Installing decoy website..."
mkdir -p "$DECOY_ROOT"
if [[ -f "$SCRIPT_DIR/decoy/index.html" ]]; then
    cp "$SCRIPT_DIR/decoy/"* "$DECOY_ROOT/"
    echo "    → Copied decoy content from infra/decoy/"
else
    # Fallback: minimal placeholder so nginx doesn't 404 on first start
    cat > "$DECOY_ROOT/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Welcome</title></head>
<body><h1>Service Online</h1><p>Nothing to see here.</p></body>
</html>
HTMLEOF
    echo "    → Installed minimal placeholder (copy infra/decoy/ for the full decoy site)"
fi

# Deny directory listing
cat > "$DECOY_ROOT/robots.txt" <<'EOF'
User-agent: *
Disallow: /ws
EOF

chown -R www-data:www-data "$DECOY_ROOT"
chmod -R 755 "$DECOY_ROOT"

# ── 6. Nginx configuration ────────────────────────────────────────────────────
echo "[6/9] Configuring Nginx..."
cp "$SCRIPT_DIR/nginx.conf" "$NGINX_CONF"
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" "$NGINX_CONF"
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/stealthvpn
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx

# ── 7. TLS certificate via Let's Encrypt ─────────────────────────────────────
echo "[7/9] Obtaining TLS certificate for $DOMAIN..."
certbot --nginx -d "$DOMAIN" \
    --non-interactive --agree-tos \
    --email "$EMAIL" \
    --redirect
systemctl reload nginx
echo "    → Certificate issued. Expiry check: certbot certificates"

# ── 8. Auto-renewal (TLS certificates) ───────────────────────────────────────
echo "[8/9] Configuring certificate auto-renewal..."
# Remove any duplicate entries before adding
CRON_LINE="0 3 * * * certbot renew --quiet && systemctl reload nginx"
( crontab -l 2>/dev/null | grep -v "certbot renew" ; echo "$CRON_LINE" ) | crontab -
echo "    → Certbot renewal scheduled at 03:00 daily"

# ── 9. Systemd service ────────────────────────────────────────────────────────
echo "[9/9] Installing systemd service..."
cp "$SCRIPT_DIR/server.service" "$SERVICE_PATH"
systemctl daemon-reload
systemctl enable stealthvpn

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           StealthVPN Setup Complete!                     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Domain:   $DOMAIN"
echo "║  Decoy:    $DECOY_ROOT"
echo "║  Logs:     $LOG_DIR"
echo "║  Service:  $SERVICE_PATH"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                             ║"
echo "║                                                          ║"
echo "║  1. Build the server binary:                             ║"
echo "║     cargo build --release -p server                      ║"
echo "║                                                          ║"
echo "║  2. Install the binary:                                  ║"
echo "║     sudo cp target/release/stealthvpn-server $BINARY_PATH"
echo "║                                                          ║"
echo "║  3. Start the VPN:                                       ║"
echo "║     sudo systemctl start stealthvpn                      ║"
echo "║                                                          ║"
echo "║  4. Monitor:                                             ║"
echo "║     sudo journalctl -u stealthvpn -f                     ║"
echo "║     sudo systemctl status stealthvpn                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
