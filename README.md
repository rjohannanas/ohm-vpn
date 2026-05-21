# StealthVPN — Documentación Completa v1.0

## Índice

1. [Descripción General](#descripción-general)
2. [Arquitectura](#arquitectura)
3. [Instalación del Servidor](#instalación-del-servidor)
4. [Instalación del Cliente](#instalación-del-cliente)
5. [Uso](#uso)
6. [Configuración de Obfuscación](#configuración-de-obfuscación)
7. [Seguridad](#seguridad)
8. [Rotación de Claves](#rotación-de-claves)
9. [Monitoreo y Logs](#monitoreo-y-logs)
10. [Resolución de Problemas](#resolución-de-problemas)
11. [Referencia de Flags CLI](#referencia-de-flags-cli)

---

## Descripción General

StealthVPN es una VPN personal diseñada para resistir inspección profunda de paquetes (DPI), en particular la de firewalls corporativos como Fortinet. El tráfico es **indistinguible de HTTPS normal** a nivel de red.

**Características principales:**

| Característica | Descripción |
|---------------|-------------|
| Transporte | WebSocket sobre TLS 1.3 (puerto 443) |
| Criptografía | X25519 ECDH + ChaCha20-Poly1305 + HKDF-SHA256 |
| Anti-DPI | Padding aleatorio, timing jitter, fragmentación, normalización de tamaños |
| Forward Secrecy | Claves efímeras por sesión + rotación intra-sesión (cada hora) |
| Servidor señuelo | Sitio web real sirviendo en el mismo puerto 443 |
| DNS | Prevención automática de DNS leaks (redirige a 1.1.1.1 vía túnel) |

---

## Arquitectura

```
[Cliente Linux]
      │
      │  TLS 1.3 + WebSocket (puerto 443)
      │  Tráfico obfuscado: padding + jitter + fragmentación
      ▼
[Servidor — Nginx]
      │
      ├── GET / → Nexova Cloud (sitio señuelo)
      └── GET /ws → Servidor VPN Rust (127.0.0.1:8080)
                        │
               X25519 ECDH handshake
               ChaCha20-Poly1305 encryption
                        │
                        ▼
               [Internet / Destino]
```

### Flujo del handshake

```
Cliente                                    Servidor
   │── WebSocket Upgrade (TLS 1.3) ───────►│
   │◄── 101 Switching Protocols ───────────│
   │── ClientHello { ephemeral_pub } ──────►│
   │◄── ServerHello { ephemeral_pub, sid } ─│
   │   [ECDH → session keys via HKDF]      │
   │── ClientReady { sid } (encrypted) ────►│
   │◄── SessionEstablished { ip, mask } ───│
   │        [Tráfico VPN cifrado]           │
```

---

## Instalación del Servidor

### Requisitos

- Ubuntu 22.04 LTS (recomendado)
- Dominio apuntando al servidor (para certificado TLS)
- Puerto 443 abierto
- Rust toolchain (`rustup.rs`)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/your-org/ohm-vpn
cd ohm-vpn

# 2. Compilar el servidor
cargo build --release -p server

# 3. Instalar el binario
sudo cp target/release/stealthvpn-server /usr/local/bin/

# 4. Ejecutar el script de instalación (como root)
sudo bash infra/setup.sh vpn.tudominio.com admin@tudominio.com

# 5. Iniciar el servicio
sudo systemctl start stealthvpn
sudo systemctl status stealthvpn
```

El script de instalación:
- Instala Nginx, Certbot, ufw
- Configura el firewall (puertos 22, 80, 443)
- Activa IP forwarding
- Crea el usuario de sistema `stealthvpn`
- Despliega el sitio señuelo Nexova Cloud
- Obtiene certificado TLS de Let's Encrypt
- Configura renovación automática de certificados
- Instala y habilita el servicio systemd

---

## Instalación del Cliente

### Requisitos

- Linux (Ubuntu/Debian/Arch)
- Rust toolchain
- Ejecutar como **root** (necesario para crear interfaz TUN y modificar rutas)

### Pasos

```bash
# 1. Compilar el cliente
cargo build --release -p client

# 2. Instalar el binario (opcional)
sudo cp target/release/stealthvpn-client /usr/local/bin/

# 3. Conectar (siempre ejecutar como root)
sudo stealthvpn-client connect --server vpn.tudominio.com
```

---

## Uso

### Conectar

```bash
# Conexión básica
sudo stealthvpn-client connect --server vpn.tudominio.com

# Con perfil de obfuscación agresivo
sudo stealthvpn-client connect --server vpn.tudominio.com --obfuscation aggressive

# Modo de prueba sin verificación TLS (solo desarrollo)
sudo stealthvpn-client connect --server 1.2.3.4 --insecure
```

### Desconectar

Presiona `Ctrl-C` en la terminal donde corre `connect`. El cliente:
1. Envía frame `Disconnect` al servidor
2. Restaura las rutas del sistema originales
3. Restaura `/etc/resolv.conf` original

### Verificar estado del túnel

```bash
# Ver interfaz TUN asignada
ip addr show tun0

# Verificar IP pública (debe ser la del servidor VPN)
curl https://ipinfo.io/ip

# Verificar ausencia de DNS leaks
cat /etc/resolv.conf   # debe mostrar 1.1.1.1
```

---

## Configuración de Obfuscación

StealthVPN ofrece tres perfiles predefinidos:

| Perfil | Padding | Jitter | Fragmentación | Normalización | Uso |
|--------|---------|--------|---------------|---------------|-----|
| `none` | 0 B | 0 ms | deshabilitada | no | Benchmarks / redes de confianza |
| `default` | 16–256 B | 0–5 ms | > 1400 B | no | Uso diario |
| `aggressive` | 64–512 B | 0–20 ms | > 900 B | sí | Firewalls muy restrictivos |

```bash
# Perfil agresivo (máxima protección contra DPI)
sudo stealthvpn-client connect --server vpn.tudominio.com --obfuscation aggressive

# Configuración manual (overrides el preset)
sudo stealthvpn-client connect \
  --server vpn.tudominio.com \
  --obfuscation default \
  --max-padding 512 \
  --max-jitter-ms 15 \
  --fragment-threshold 1200 \
  --normalize-sizes
```

### Normalización de tamaños

Con `--normalize-sizes`, todos los frames se padean al siguiente bucket de tamaño:

`128 → 256 → 512 → 1024 → 1280 → 1452 → 2048 → 4096 → 8192 → 16384 bytes`

Esto elimina el análisis estadístico de distribución de tamaños de paquetes, que es una de las técnicas más efectivas de DPI fingerprinting.

---

## Seguridad

### Modelo de amenaza

| Amenaza | Mitigación |
|---------|-----------|
| Inspección DPI de tráfico | WebSocket/TLS 1.3 + obfuscación |
| Fingerprinting por tamaño | Padding aleatorio + normalización por buckets |
| Fingerprinting por timing | Jitter aleatorio (0–20 ms configurable) |
| Detección por patrones | Ciphertext uniforme de alta entropía (>7 bits/byte) |
| DNS leaks | `DnsGuard` reemplaza `/etc/resolv.conf` durante la sesión |
| Inspección del servidor | Sitio señuelo activo en el mismo dominio/puerto |
| Compromiso de sesión | Claves efímeras X25519 (nueva ECDH por conexión) |
| Registro de tráfico histórico | Rotación de claves intra-sesión cada 1 hora |
| Caducidad de certificados | Renovación automática vía Certbot (cron diario 03:00) |

### Primitivas criptográficas

- **Intercambio de claves:** X25519 (ECDH) — claves efímeras, nunca reutilizadas
- **Derivación de claves:** HKDF-SHA256 con contextos separados por dirección
- **Cifrado:** ChaCha20-Poly1305 (AEAD) — autenticación integrada
- **Nonces:** Contador monotónico (64-bit LE), nunca reutilizados en la misma sesión
- **Padding:** Bytes criptográficamente aleatorios (OsRng)

### Auditoría de seguridad del código criptográfico

El código criptográfico en `common/src/crypto.rs` usa exclusivamente librerías auditadas:

| Librería | Versión | Propósito |
|----------|---------|-----------|
| `x25519-dalek` | 2.0 | X25519 ECDH |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD |
| `hkdf` | 0.12 | HKDF-SHA256 |
| `zeroize` | 1.7 | Limpieza de material clave en memoria |

**Checklist de auditoría:**
- [x] No se implementa criptografía propia — se usan librerías auditadas por la comunidad
- [x] `SessionKey` implementa `ZeroizeOnDrop` — la clave se borra de memoria al liberar
- [x] Nonces son únicos por construcción (contador monotónico con overflow check)
- [x] HKDF separa claves por dirección (c2s vs s2c) y por generación (rotación)
- [x] Handshake es resistente a replay (session_id verificado por el servidor)
- [x] Rotación de claves usa contextos HKDF distintos por `rotation_id`
- [ ] Auditoría externa por terceros — **pendiente para v1.1**

---

## Rotación de Claves

### Rotación de claves de sesión (intra-sesión)

Implementada en `common/src/key_rotation.rs`. La rotación ocurre cada **1 hora** por defecto sin interrumpir la conexión.

El protocolo de rotación:
1. El iniciador genera un nuevo par de claves X25519 efímero
2. Envía `KeyRotateRequest { ephemeral_pub, rotation_id }` cifrado con la clave actual
3. El respondedor contesta con `KeyRotateAccept { ephemeral_pub, rotation_id }`
4. Ambos derivan nuevas claves con `HKDF-SHA256(shared_secret, info=rotation_context)`
5. El iniciador envía `KeyRotateComplete` con la **nueva** clave para confirmar
6. A partir de este punto, ambos usan las nuevas claves

> **Estado actual:** El módulo `key_rotation.rs` define el protocolo, las estructuras de mensajes, y el `RotationTimer`. La integración en el loop de `tunnel.rs` se completará en v1.1.

### Rotación de certificados TLS

Los certificados Let's Encrypt se renuevan automáticamente. El cron instalado por `setup.sh`:

```cron
0 3 * * * certbot renew --quiet && systemctl reload nginx
```

Los certificados se renuevan ~30 días antes de expirar. Verificar estado:

```bash
certbot certificates
```

---

## Monitoreo y Logs

### Logs del servidor

```bash
# Seguir logs en tiempo real
sudo journalctl -u stealthvpn -f

# Ver las últimas 100 líneas
sudo journalctl -u stealthvpn -n 100

# Filtrar solo errores
sudo journalctl -u stealthvpn -p err
```

### Métricas básicas

El servidor logea periódicamente (cada 60 s por defecto):
```
INFO stealthvpn: Active sessions: 3
```

Para métricas avanzadas (Prometheus + Grafana), configurar en v1.1.

### Alertas recomendadas

| Evento | Acción |
|--------|--------|
| `Session removed` masivo en poco tiempo | Posible escaneo de firewalls |
| `Decrypt error` frecuente | Verificar versiones cliente/servidor |
| `IP address pool exhausted` | Aumentar subnet o reducir `max_clients` |
| `TUN read error` | Verificar permisos CAP_NET_ADMIN del servicio |

---

## Resolución de Problemas

### El cliente no conecta

```bash
# Verificar que el servidor está corriendo
sudo systemctl status stealthvpn

# Verificar que nginx pasa el WebSocket correctamente
curl -s -o /dev/null -w "%{http_code}" https://vpn.tudominio.com/ws
# Esperado: 426 (Upgrade Required) — eso significa que nginx enruta /ws correctamente

# Verificar certificado TLS
curl -v https://vpn.tudominio.com/ 2>&1 | grep "SSL certificate"
```

### DNS leaks tras conectar

```bash
# Verificar que resolv.conf fue modificado
cat /etc/resolv.conf
# Debe mostrar: nameserver 1.1.1.1

# Si no fue modificado, el cliente necesita permisos root
sudo stealthvpn-client connect --server vpn.tudominio.com
```

### Tráfico no tunelizado

```bash
# Verificar que la ruta por defecto pasa por tun0
ip route show
# Debe haber una ruta default via tun0 (o similar)

# Verificar que la IP del servidor tiene ruta directa (no por tun0)
ip route get <SERVER_IP>
```

### El servidor evicta sesiones muy rápido

Ajustar el timeout de idle en `session.rs` (`SESSION_IDLE_TIMEOUT`) o asegurarse de que el heartbeat del cliente está activo (default: cada 25 s, timeout de evicción: 120 s).

---

## Referencia de Flags CLI

### `stealthvpn-server`

| Flag | Default | Descripción |
|------|---------|-------------|
| `--listen` | `127.0.0.1:8080` | Dirección de escucha del servidor WebSocket |
| `--server-ip` | `10.8.0.1` | IP del servidor en la interfaz TUN |
| `--subnet` | `10.8.0.0` | Base de la subred VPN |
| `--netmask` | `255.255.255.0` | Máscara de subred |
| `--max-clients` | `50` | Máximo de clientes simultáneos |
| `--min-padding` | `16` | Padding mínimo por paquete (bytes) |
| `--max-padding` | `256` | Padding máximo por paquete (bytes, 0=deshabilitado) |
| `--max-jitter-ms` | `5` | Jitter máximo antes de enviar (ms, 0=deshabilitado) |
| `--fragment-threshold` | `1400` | Fragmentar paquetes mayores a N bytes (0=deshabilitado) |
| `--normalize-sizes` | `false` | Normalizar frames a buckets de tamaño predefinidos |
| `--eviction-interval-secs` | `60` | Intervalo de limpieza de sesiones inactivas (s) |

### `stealthvpn-client connect`

| Flag | Default | Descripción |
|------|---------|-------------|
| `--server` / `-s` | (requerido) | Dirección del servidor VPN |
| `--port` / `-p` | `443` | Puerto del servidor |
| `--path` | `/ws` | Ruta WebSocket del endpoint VPN |
| `--insecure` | `false` | Deshabilitar verificación TLS (solo pruebas) |
| `--obfuscation` | `default` | Perfil: `none`, `default`, `aggressive` |
| `--min-padding` | (del perfil) | Override: padding mínimo (bytes) |
| `--max-padding` | (del perfil) | Override: padding máximo (bytes) |
| `--max-jitter-ms` | (del perfil) | Override: jitter máximo (ms) |
| `--fragment-threshold` | (del perfil) | Override: umbral de fragmentación (bytes) |
| `--normalize-sizes` | `false` | Override: activar normalización por buckets |
| `--heartbeat-interval-secs` | `25` | Intervalo de heartbeats al servidor (s, 0=deshabilitado) |
