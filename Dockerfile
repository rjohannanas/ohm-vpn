# Build stage
FROM rust:slim-bullseye AS builder

WORKDIR /usr/src/ohm-vpn
COPY . .

# Build only the server for release
RUN cargo build --release -p server

# Runtime stage
FROM debian:bullseye-slim

# Install iproute2 for ip commands (optional but helpful for debugging inside container)
RUN apt-get update && apt-get install -y iproute2 iptables && rm -rf /var/lib/apt/lists/*

# Create a dedicated user, but the container might need to run as root to manage TUN interfaces
# For simplicity and VPN requirements, we run as root in the container (secured by docker isolation)

WORKDIR /app
COPY --from=builder /usr/src/ohm-vpn/target/release/stealthvpn-server /usr/local/bin/

# Expose the port the server will listen on internally
EXPOSE 8080

# Run the server. We listen on 0.0.0.0 so Traefik can route to it.
ENTRYPOINT ["stealthvpn-server", "--listen", "0.0.0.0:8080"]
