@echo off
echo ==================================================
echo   P2P CLOUD AUTH - Distributed Mode
echo ==================================================
if not exist .env copy .env.example .env
pip install -r requirements.txt --quiet

echo.
echo   Hub:    http://localhost:8000
echo   Peer A: http://localhost:8001  (open in Chrome)
echo   Peer B: http://localhost:8002  (open in Firefox)
echo   Monitor:http://localhost:8000/monitor
echo.

start "HUB"    cmd /k python hub.py
timeout /t 2 /nobreak >nul
start "PEER_A" cmd /k python peer.py 8001
start "PEER_B" cmd /k python peer.py 8002

echo All servers started in separate windows.
pause
