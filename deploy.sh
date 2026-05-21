#!/bin/bash
set -e

echo "========================================="
echo "   Desplegando StealthVPN (Servidor)     "
echo "========================================="

# Reconstruir y levantar el contenedor del servidor VPN
echo "[1/3] Construyendo contenedor del servidor..."
docker compose up -d --build vpn

# Compilar el binario del cliente
echo "[2/3] Compilando el cliente de descarga localmente..."
cargo build --release -p client

echo "========================================="
echo "[3/3] ¡Despliegue finalizado con éxito!"
echo "El cliente actualizado ya está disponible en:"
echo "https://ohm.seteloee.com/download"
echo "========================================="
