# NetSnoop: Real-Time Network Packet Sniffer and Protocol Analyzer in C

**Course:** Data Structures Using C  
**Program:** Master of Computer Applications (MCA) – 1st Semester (2026–2027)  
**Institution:** Jaypee Institute of Information Technology, Noida  
**Department:** Department of Computer Applications  

### Project Members
- **Gautam Singhal** (Enrollment No: `992610170060`)
- **Somya** (Enrollment No: `992610170047`)
- **Parth Upadhyay** (Enrollment No: `992610170054`)

---

## 1. Abstract
**NetSnoop** is a lightweight, terminal-based network packet sniffer and protocol analyzer developed in C. It captures live packets from a selected interface (or reads offline `.pcap` capture files), parses Ethernet, IPv4, TCP, UDP, and ICMP headers, and displays key information such as hardware addresses, IP addresses, port numbers, transport protocol, packet size, and timestamps. The project demonstrates core C programming concepts including structures, pointers, bitwise operations, memory management, and data structures (hash tables and linked lists for anomaly detection) while providing a foundation for traffic analysis and basic security monitoring.

---

## 2. Architecture & Pipeline

```
[ Network Interface / PCAP File ]
                │
                ▼
        ┌───────────────┐
        │    CAPTURE    │ (libpcap: capture_init, capture_start, capture_stop)
        └───────┬───────┘
                │ Raw Packet Bytes
                ▼
        ┌───────────────┐
        │    PARSER     │ (Ethernet -> IPv4 -> TCP / UDP / ICMP)
        └───────┬───────┘
                │ ParsedPacket Struct
                ▼
        ┌───────────────┐
        │    FILTER     │ (Protocol, Port, Source/Destination IP)
        └───────┬───────┘
                │ Matched Packets
        ┌───────┴────────────────────────┐
        ▼                                ▼
┌───────────────┐                ┌───────────────┐
│    DISPLAY    │                │  STATISTICS   │
│ & LOG FILE    │                │  & DETECTOR   │
└───────────────┘                └───────────────┘
(ANSI Terminal /                (Packets, Bytes, Rate,
 Hex Dump / Log)                 SYN Flood & Port Scan Alerts)
```

---

## 3. Project Structure

```
├── include/
│   ├── types.h         # Protocol header structs, enums & state definitions
│   ├── capture.h       # Packet capture module (libpcap abstraction)
│   ├── parser.h        # Protocol decoding functions
│   ├── filter.h        # Packet filtering rules engine
│   ├── display.h       # Terminal formatting, banner & payload dump
│   ├── stats.h         # Running statistics and throughput calculator
│   └── detector.h      # Security anomaly detector (SYN flood & port scan)
├── src/
│   ├── main.c          # Entry point, signal handling (Ctrl+C), CLI options
│   ├── capture.c       # Live interface capture & offline PCAP playback
│   ├── parser.c        # Bitwise extraction and protocol header parser
│   ├── filter.c        # Protocol, port, and IP address matching logic
│   ├── display.c       # Output formatting and hex/ASCII payload view
│   ├── stats.c         # Real-time counter metrics & packets/sec computation
│   └── detector.c      # Hash-table based IP tracking & anomaly alerts
├── tests/
│   └── test_parser.c   # Unit test suite verifying parsers and filters
├── samples/
│   ├── generate_pcap.py       # Python script generating realistic PCAP samples
│   └── sample_traffic.pcap    # Pre-generated sample PCAP file
├── Makefile            # Build configuration (build, test, run, clean)
└── README.md           # Project documentation
```

---

## 4. Key C Concepts & Data Structures Used

1. **C Structures (`__attribute__((packed))`):** Direct byte-mapping for Ethernet (14B), IPv4 (20B), TCP (20B), UDP (8B), and ICMP headers.
2. **Bitwise Operations:**
   - IPv4 Version & IHL extraction: `version = (ver_ihl >> 4) & 0x0F`, `ihl = (ver_ihl & 0x0F) * 4`.
   - TCP Data Offset: `(data_offset_res >> 4) * 4`.
   - TCP Flags Masking: `SYN (0x02)`, `ACK (0x10)`, `FIN (0x01)`, `RST (0x04)`, `PSH (0x08)`, `URG (0x20)`.
3. **Pointers & Pointer Arithmetic:** Offsetting pointers past link and network headers to inspect transport layers and payload data.
4. **Byte-Order Conversion:** Applying `ntohs()` and `ntohl()` for network-to-host endian conversions.
5. **Hash Table with Linked-List Collision Chaining (`detector.c`):** An IP tracking hash table indexed by IPv4 address to detect SYN flood traffic (>30 SYN packets) and port scans (>10 unique destination ports).

---

## 5. Prerequisites & Compilation

### Requirements
- GCC or Clang (C99/C11 standard)
- GNU Make
- `libpcap` development library (`libpcap-dev` on Ubuntu/Debian)

### On Linux or WSL (Ubuntu):
```bash
# Install dependencies (if not already installed)
sudo apt update
sudo apt install -y build-essential libpcap-dev

# Compile NetSnoop
make all

# Run unit tests
make test
```

---

## 6. How to Run

### A. Interactive Management Console (Recommended)
Simply launch `./bin/netsnoop` without arguments (or with `-C`), or double-click `run_demo.bat` on Windows:
```bash
./bin/netsnoop
# or with root permissions for live capture:
sudo ./bin/netsnoop
```

This launches the interactive prompt:
```
=================================================================
  NetSnoop v1.0 - Real-Time Packet Sniffer & Protocol Analyzer   
  Data Structures Using C | MCA Semester 1 (2026-2027)           
=================================================================
NetSnoop Management Console v1.0
Type 'help' for command list, 'menu' for options menu, or select [1-9].

netsnoop>
```

#### Interactive Commands & Menu Options
You can either type commands or choose numbered menu options `1` through `9`:
- `[1]` / `list` : List available network interfaces.
- `[2]` / `capture [iface] [count]` : Start live capture (press `Ctrl+C` to return cleanly to console).
- `[3]` / `replay [file.pcap] [count]` : Analyze offline PCAP file.
- `[4]` / `filter [protocol] [port]` : Configure filters (e.g. `filter TCP 443`).
- `[5]` / `stats` : Display cumulative packet and throughput statistics.
- `[6]` / `verbose <on|off>` : Toggle hex/ASCII payload inspection.
- `[7]` / `log <file|off>` : Enable or disable writing logs to file.
- `[8]` / `clear` : Clear console screen.
- `[9]` / `exit` : Quit console.

---

### B. Direct Command-Line Mode (One-Shot / Scripts)
```bash
# Capture from default interface
sudo ./bin/netsnoop

# Capture from specific interface (e.g. eth0)
sudo ./bin/netsnoop -i eth0

# Capture only TCP traffic on port 443 (HTTPS)
sudo ./bin/netsnoop -i eth0 -p TCP -P 443

# Capture with verbose payload hex-dump and log to file
sudo ./bin/netsnoop -i eth0 -v -l netsnoop.log
```

### C. Offline PCAP File Analysis (No root required!)
NetSnoop includes full support for reading offline `.pcap` files, enabling testing and evaluation without live network traffic or elevated privileges:
```bash
# Run against the included sample PCAP
./bin/netsnoop -r samples/sample_traffic.pcap

# Filter only DNS packets
./bin/netsnoop -r samples/sample_traffic.pcap -p DNS

# Verbose inspection of HTTP traffic with hex dump
./bin/netsnoop -r samples/sample_traffic.pcap -p HTTP -v
```

---

## 7. Sample Output

```
=================================================================
  NetSnoop v1.0 - Real-Time Packet Sniffer & Protocol Analyzer   
  Data Structures Using C | MCA Semester 1 (2026-2027)           
=================================================================
[*] Reading from PCAP file: samples/sample_traffic.pcap
NetSnoop v1.0 – Starting capture...
Filter: proto=ALL, port=0
Press Ctrl+C to stop.

[22:13:20] TCP 192.168.1.100:54321 → 142.250.190.78:443 [SYN] Len=54
[22:13:20] TCP 142.250.190.78:443 → 192.168.1.100:54321 [SYN-ACK] Len=54
[22:13:21] TCP 192.168.1.100:54321 → 142.250.190.78:443 [ACK] Len=54
[22:13:21] TCP 192.168.1.100:51234 → 93.184.216.34:80 [ACK-PSH] Len=101
[22:13:21] TCP 93.184.216.34:80 → 192.168.1.100:51234 [ACK-PSH] Len=121
[22:13:22] UDP 192.168.1.100:49152 → 8.8.8.8:53 [DNS] Len=71
[22:13:22] ICMP 192.168.1.100 → 8.8.8.8 [Echo Request] Len=74
[22:13:22] ICMP 8.8.8.8 → 192.168.1.100 [Echo Reply] Len=74
[22:13:23] TCP 10.0.0.99:40000 → 192.168.1.1:21 [SYN] Len=54
[22:13:23] TCP 10.0.0.99:40001 → 192.168.1.1:22 [SYN] Len=54
[!] SECURITY ALERT: Possible Port Scan from 10.0.0.99 (> 10 unique ports queried)

========================================================
               NetSnoop Final Statistics                
========================================================
 Elapsed Time        : 3.12 seconds
 Total Packets       : 20
 Total Transferred   : 1.22 KB (1251 bytes)
 Average Throughput  : 0.39 KB/s (6.4 pkts/sec)
--------------------------------------------------------
 Protocol Breakdown:
   TCP Packets       : 17 (85.0%)
   UDP Packets       : 1 (5.0%)
   ICMP Packets      : 2 (10.0%)
   Other/ARP/ETH     : 0 (0.0%)
--------------------------------------------------------
 Application / Flag Indicators:
   HTTP / HTTPS      : 4 / 4
   DNS Requests/Resp : 1
   TCP SYN / FIN/RST : 14 / 0
========================================================
```

---

## 8. Command-Line Options Reference

| Flag | Argument | Description |
|------|----------|-------------|
| `-i` | `<dev>` | Interface to capture from (e.g., `eth0`, `wlan0`) |
| `-r` | `<file.pcap>` | Read and analyze offline PCAP capture file |
| `-p` | `<proto>` | Filter protocol: `ALL`, `TCP`, `UDP`, `ICMP`, `HTTP`, `DNS` |
| `-P` | `<port>` | Filter by port number (e.g., `80`, `443`, `53`) |
| `-s` | `<ip>` | Filter by source IPv4 address |
| `-d` | `<ip>` | Filter by destination IPv4 address |
| `-c` | `<count>` | Stop capturing after `<count>` matching packets |
| `-l` | `<file>` | Write packet logs and final report to a text file |
| `-v` | none | Enable verbose mode (shows header fields and payload hex dump) |
| `-L` | none | List available network devices and their IP addresses |
| `-h` | none | Display help manual |
