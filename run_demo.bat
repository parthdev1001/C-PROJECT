@echo off
title NetSnoop - Simple Packet Sniffer
echo =================================================================
echo   NetSnoop - Simple Packet Sniffer
echo =================================================================
wsl -d Ubuntu --cd "%~dp0" sh -c "make all && ./bin/netsnoop -r samples/sample_traffic.pcap"
pause
