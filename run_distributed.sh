#!/bin/bash
# run_distributed.sh — starts hub + 2 peer nodes

set -e
echo "=================================================="
echo "  P2P CLOUD AUTH — Distributed Mode"
echo "=================================================="

# Copy .env if not present
[ ! -f .env ] && cp .env.example .env && echo "  Created .env from .env.example"

# Install dependencies
pip install -r requirements.txt --quiet

echo ""
echo "  Starting HUB    →  http://localhost:8000"
echo "  Starting PEER A →  http://localhost:8001"
echo "  Starting PEER B →  http://localhost:8002"
echo "  Monitor         →  http://localhost:8000/monitor"
echo ""
echo "  Open Peer A in Chrome:  http://localhost:8001"
echo "  Open Peer B in Firefox: http://localhost:8002"
echo ""
echo "  Press CTRL+C to stop all servers."
echo "=================================================="

trap "echo ''; echo 'Shutting down...'; kill 0" SIGINT SIGTERM

python hub.py &
sleep 1
python peer.py 8001 &
python peer.py 8002 &

wait
