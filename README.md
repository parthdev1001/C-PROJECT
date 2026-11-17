# NetSnoop — Simple Packet Sniffer in C

**Course:** Data Structures Using C
**Program:** MCA, Semester 1
**Project level:** College demonstration

## What this project does

NetSnoop reads network packets and prints a short, human-readable summary. It understands:

- Ethernet frames
- IPv4 packets
- TCP packets (addresses, ports, and flags such as SYN/ACK)
- UDP packets
- ICMP packets (for example, ping requests and replies)

It can read the included sample capture file, so the project can be demonstrated without administrator permission or an internet connection. It can also capture live traffic from a network interface.

## Simple program flow

```
PCAP file or network interface
            |
            v
        libpcap reads bytes
            |
            v
 Ethernet -> IPv4 -> TCP / UDP / ICMP parser
            |
            v
      Print one-line packet summary
            |
            v
       Print packet-count summary
```

## Project files

```
include/
  types.h       Packet-header structures and ParsedPacket structure
  capture.h     Functions for live/offline packet capture
  parser.h      Functions that decode packet headers
  display.h     Functions that print results
src/
  main.c        Program options, callback, and simple counters
  capture.c     libpcap setup and device listing
  parser.c      Ethernet, IPv4, TCP, UDP, and ICMP parsing
  display.c     One-line packet output and help text
samples/
  sample_traffic.pcap   Safe demo input with TCP, UDP, and ICMP packets
  generate_pcap.py      Optional script that creates the demo input again
tests/
  test_parser.c          Small parser tests
```

The old interactive console, filters, logging, payload dump, and attack detector were removed so the project stays easy to understand and explain.

## Build and run

### Recommended demo (works without administrator permission)

On Ubuntu or WSL, install the one required library once:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

Build and run the included sample:

```bash
make
./bin/netsnoop -r samples/sample_traffic.pcap
```

From Windows, double-click `run_demo.bat` if WSL with Ubuntu is installed. It builds the project and opens the same sample demonstration.

Run the small tests:

```bash
make test
```

### Live capture (optional)

List interface names first:

```bash
./bin/netsnoop -L
```

Then capture a fixed number of packets. Live capture usually needs administrator/root permission:

```bash
sudo ./bin/netsnoop -i eth0 -c 10
```

## Command-line options

| Option | Meaning |
|---|---|
| `-r file.pcap` | Read packets from a PCAP file (best for presentation) |
| `-i interface` | Capture live packets from one interface |
| `-c number` | Stop after this many packets |
| `-L` | List available interfaces |
| `-h` | Show help |

Do not use `-i` and `-r` together.

## Sample output

```
[22:13:20] TCP  192.168.1.100:54321 -> 142.250.190.78:443  [SYN]  (54 bytes)
[22:13:20] TCP  142.250.190.78:443 -> 192.168.1.100:54321  [SYN-ACK]  (54 bytes)
[22:13:21] UDP  192.168.1.100:49152 -> 8.8.8.8:53  (71 bytes)
[22:13:22] ICMP 192.168.1.100 -> 8.8.8.8  Echo Request  (74 bytes)

--- Capture Summary ---
Packets: 20 | TCP: 17 | UDP: 1 | ICMP: 2 | Other: 0
```

## How to explain it in your viva

Start with this:

> “NetSnoop is a basic packet sniffer written in C. It uses the libpcap library to read raw network packets. My program then moves through the packet headers—Ethernet, IPv4, and TCP/UDP/ICMP—and prints useful fields such as IP address, port number, TCP flags, and packet size.”

Then explain the files in this order:

1. `main.c` chooses a PCAP file or live interface, and gives libpcap a callback function.
2. For every packet, libpcap calls `packet_callback` in `main.c`.
3. `parser.c` reads headers using structures and pointer arithmetic. It uses `ntohs()` and `ntohl()` because network byte order is different from the computer's byte order.
4. `display.c` prints the decoded information.
5. At the end, `main.c` prints counts for TCP, UDP, ICMP, and other packets.

Useful C concepts to mention:

- **Structures:** Header structures represent Ethernet, IPv4, TCP, UDP, and ICMP layouts.
- **Pointers:** The parser moves a pointer forward after each header to reach the next one.
- **Bitwise operations:** IPv4 version/header length and TCP flags are stored in bits.
- **Enums:** `PROTO_TCP`, `PROTO_UDP`, and `PROTO_ICMP` make protocol decisions readable.
- **Callback function:** libpcap calls our function whenever it receives a packet.

For the presentation, run the sample-PCAP command, point out one TCP handshake (`SYN`, `SYN-ACK`, `ACK`), one UDP packet, and one ICMP ping. This is safe, repeatable, and enough for a college project.

## Limits (say these honestly)

This is an educational parser, not a security product. It reads Ethernet/IPv4 traffic only; it does not decrypt HTTPS, reassemble fragmented packets, or analyze every network protocol.
