#!/bin/sh
# setup-dns.sh — Configure macOS to resolve *.lab.local via CoreDNS
# Run once after docker compose up -d
#
# CoreDNS runs on port 5353 inside the container, exposed on host port 5353.

set -e

echo "=== Setting up macOS resolver for lab.local ==="
echo ""

sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1
port 5353" | sudo tee /etc/resolver/lab.local

echo ""
echo "✅ *.lab.local will now resolve via CoreDNS on port 5353"
echo "   (UDP/TCP on host port 5353)"
echo ""
echo "Test: ping -c1 auth.lab.local"
echo "Expected: PING auth.lab.local (127.0.0.1):"