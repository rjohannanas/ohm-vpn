# StealthVPN

Personal anti-detection VPN built in Rust. Tunnels traffic over WebSocket + TLS 1.3 on port 443, making it indistinguishable from regular HTTPS traffic to DPI firewalls such as Fortinet.

## Architecture

```
[Client - PC/Mobile]
        │
        │  TLS 1.3 + WebSocket (port 443)
        │  Obfuscated traffic (padding + jitter)
        ▼
[Server - Nginx]
        │
        ├─── /    → Decoy website (static HTML)
        └─── /ws  → VPN handler (proxied internally)
                        │
                        ▼
               [StealthVPN Server (Rust)]
                        │
               ChaCha20-Poly1305 + X25519
                        │
                        ▼
               [Internet / Destination]
```

## Quick Start

### Prerequisites

- Rust 1.75+
- A Linux server (Ubuntu 22.04 recommended) with a public IP
- A domain name pointing to that IP

### Build

```bash
# Build everything
cargo build --release

# Run common tests (crypto, protocol, obfuscation)
cargo test -p common
```

### Server Deployment (Google Cloud / any VPS)

```bash
# 1. Copy server binary
scp target/release/stealthvpn-server user@your-server:/usr/local/bin/

# 2. Run setup script (as root)
sudo bash infra/setup.sh your-domain.com

# 3. Start service
sudo systemctl start stealthvpn
```

### Client Usage

```bash
# Connect to VPN
sudo stealthvpn-client connect --server your-domain.com

# Check status
stealthvpn-client status

# Disconnect
sudo stealthvpn-client disconnect
```

## Project Structure

```
stealthvpn/
├── common/          # Shared: crypto, protocol, obfuscation
├── server/          # VPN server binary
├── client/          # VPN client binary (CLI)
├── infra/           # Nginx config, systemd unit, setup script
└── docs/            # Protocol spec, architecture, deployment guide
```

## Development Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Cryptography (X25519, ChaCha20, HKDF) | ✅ Done |
| 2 | TUN interface & IP routing | 🔄 Next |
| 3 | VPN server (WebSocket + sessions) | ⏳ Pending |
| 4 | VPN client (CLI + DNS leak prevention) | ⏳ Pending |
| 5 | Obfuscation & anti-detection tuning | ⏳ Pending |
| 6 | Hardening, QA, documentation | ⏳ Pending |

## Security

- **Key exchange**: X25519 (Elliptic Curve Diffie-Hellman)
- **Encryption**: ChaCha20-Poly1305 (authenticated)
- **Key derivation**: HKDF-SHA256 with direction-specific context strings
- **Transport**: TLS 1.3 (Nginx terminates, WebSocket proxied internally)
- **Certificate**: Let's Encrypt (trusted CA, auto-renewed)

> ⚠️ **For personal use only.** Ensure compliance with local laws and your organization's policies.

## License

MIT
