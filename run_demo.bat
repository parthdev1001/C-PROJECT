@echo off
title NetSnoop - Interactive Packet Sniffer Console
echo =================================================================
echo   NetSnoop - Interactive Packet Sniffer & Protocol Analyzer
echo =================================================================
wsl -d Ubuntu -e sh -c "cd '/mnt/c/Users/Parth/Desktop/C LANGUAGE PROJECT' && make all && ./bin/netsnoop"
pause
