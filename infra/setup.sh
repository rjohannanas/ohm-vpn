#!/usr/bin/env bash
# StealthVPN — Server Setup Script
# Tested on Ubuntu 22.04 LTS
# Run as root: sudo bash setup.sh YOUR_DOMAIN

set -euo pipefail

DOMAIN="${1:?Usage: $0 <your-domain>}"
VPN_USER="stealthvpn"
BINARY_PATH="/usr/local/bin/stealthvpn-server"
SERVICE_PATH="/etc/systemd/system/stealthvpn.service"
NGINX_CONF="/etc/nginx/sites-available/stealthvpn"

echo "=== StealthVPN Server Setup for domain: $DOMAIN ==="

# ── 1. System dependencies ────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx ufw

# ── 2. Firewall ───────────────────────────────────────────────────────────────
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "HTTP (ACME challenge)"
ufw allow 443/tcp  comment "HTTPS / VPN"
ufw --force enable

# ── 3. IP forwarding (required for VPN routing) ───────────────────────────────
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# ── 4. Dedicated system user ──────────────────────────────────────────────────
if ! id "$VPN_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$VPN_USER"
fi

mkdir -p /var/log/stealthvpn
chown "$VPN_USER:$VPN_USER" /var/log/stealthvpn

# ── 5. Decoy website ──────────────────────────────────────────────────────────
mkdir -p /var/www/html
cat > /var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This server is running normally.</p></body>
</html>
EOF

# ── 6. Nginx configuration ────────────────────────────────────────────────────
cp "$(dirname "$0")/nginx.conf" "$NGINX_CONF"
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" "$NGINX_CONF"
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/stealthvpn
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

# ── 7. TLS certificate via Let's Encrypt ─────────────────────────────────────
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
    --email "admin@$DOMAIN" --redirect
systemctl reload nginx

# ── 8. Auto-renewal cron ──────────────────────────────────────────────────────
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab -

# ── 9. Systemd service ────────────────────────────────────────────────────────
cp "$(dirname "$0")/server.service" "$SERVICE_PATH"
systemctl daemon-reload
systemctl enable stealthvpn

echo ""
echo "=== Setup complete! ==="
echo "Next steps:"
echo "  1. Build and copy the server binary: cp target/release/stealthvpn-server $BINARY_PATH"
echo "  2. Start the service: systemctl start stealthvpn"
echo "  3. Check status: systemctl status stealthvpn"
echo "  4. View logs: journalctl -u stealthvpn -f"
