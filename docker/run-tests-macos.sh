#!/bin/bash

# The following is an integration test for use on MacOS.
# It creates a WireGuard server running in a Docker container
# and a client running on the host machine.

set -e

INTERFACE="utun10"

cleanup() {
    echo "[+] Cleaning up..."
    docker compose -f docker-compose.yml down 2>/dev/null || true
    sudo pkill -9 wireguard-rs 2>/dev/null || true
    sleep 1

    if ifconfig "$INTERFACE" >/dev/null 2>&1; then
        echo "Warning: $INTERFACE still exists after cleanup"
    fi

    rm -f /tmp/client_key 2>/dev/null || true
    echo "[+] Cleanup complete"
}

trap cleanup EXIT

if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-wireguard-rs-binary>"
    exit 1
fi

program="$1"

if [ ! -x "$program" ]; then
    echo "[-] Error: $program does not exist or is not executable"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load keys from files
SERVER_SECRET_KEY=$(cat server-sk.key)
SERVER_PUBLIC_KEY=$(cat server-pk.key)
CLIENT_SECRET_KEY=$(cat client-sk.key)
CLIENT_PUBLIC_KEY=$(cat client-pk.key)

echo "[+] Creating WireGuard server config..."
echo "[+] Server public key: $SERVER_PUBLIC_KEY"
echo "[+] Client public key: $CLIENT_PUBLIC_KEY"

# Clean up old config and create new one
rm -rf wireguard 2>/dev/null || true
mkdir -p wireguard/wg_confs

# Create WireGuard config before starting container
cat > wireguard/wg_confs/wg0.conf <<EOF
[Interface]
 PrivateKey = $SERVER_SECRET_KEY
Address = 10.100.0.1/24, fd00::1/64
ListenPort = 51820

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.100.0.2/32, fd00::2/128
EOF

# cleanup any existing wireguard-rs
echo "[+] Cleaning up any existing wireguard-rs instances"
sudo pkill -9 wireguard-rs 2>/dev/null || true
sudo rm -rf /var/run/wireguard 2>/dev/null || true
sleep 1

echo "[+] Starting Dockerized WireGuard server"
docker compose -f docker-compose.yml up -d
sleep 1

# start wireguard-rs
echo "[+] Starting wireguard-rs on $INTERFACE"
export RUST_LOG=trace
sudo -E "$program" "$INTERFACE" > /tmp/wg_client.log 2>&1 &
WG_PID=$!
sleep 1

# wait for interface
for i in {1..20}; do
    if ifconfig "$INTERFACE" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

if ! ifconfig "$INTERFACE" >/dev/null 2>&1; then
    echo "[-] Error: $INTERFACE did not come up"
    cat /tmp/wg_client.log
    exit 1
fi

# configure interface
sudo ifconfig "$INTERFACE" inet 10.100.0.2/24 10.100.0.2
sudo ifconfig "$INTERFACE" inet6 fd00::2/64
sudo ifconfig "$INTERFACE" up

# configure WireGuard peer for the server
echo "[+] Configuring WireGuard peer"
sudo wg set "$INTERFACE" \
    private-key client-sk.key \
    listen-port 0 \
    peer "$SERVER_PUBLIC_KEY" \
        allowed-ips 10.100.0.1/32,fd00::1/128 \
        endpoint 127.0.0.1:51821 \
        persistent-keepalive 25

# Add routes
echo "[+] Updating routing table"
sudo route -n delete -host 10.100.0.1 2>/dev/null || true
sudo route -n add -host 10.100.0.1 -interface "$INTERFACE"
sudo route -n delete -inet6 -host fd00::1 2>/dev/null || true
sudo route -n add -inet6 -host fd00::1 -interface "$INTERFACE"

echo "[+] WireGuard Configuration:"
sudo wg show "$INTERFACE"

echo ""
echo "[+] Sending ping to trigger handshake..."
ping -c 1 -W 1 10.100.0.1 >/dev/null 2>&1 || true
sleep 1

echo "[+] Check that handshake completed successfully"
sudo wg show "$INTERFACE"

# Check if handshake happened
if ! sudo wg show "$INTERFACE" | grep -q "latest handshake"; then
	echo "[-] Handshake Failed."
    echo ""
    echo "Client logs:"
    cat /tmp/wg_client.log
    echo ""
    echo "Server logs:"
    docker compose -f docker-compose.yml logs wireguard-server
	exit -1
fi
echo "[+] Testing IPv4 ping to server (10.100.0.1)..."
if ! ping -c 10 -W 2 10.100.0.1; then
	echo "[-] IPv4 ping failed"
	exit -1
fi

echo "[+] Testing IPv6 ping to server (fd00::1)..."
if ! ping6 -c 10 -i 1 fd00::1%"$INTERFACE"; then
    echo "[-] IPv6 ping failed"
    exit -1
fi

echo "[+] All tests successful (IPv4 and IPv6)."
