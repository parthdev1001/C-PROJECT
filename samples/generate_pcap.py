import struct
import socket

def write_pcap(filename):
    # PCAP Global Header: magic, v_major, v_minor, thiszone, sigfigs, snaplen, network
    # network = 1 (LINKTYPE_ETHERNET)
    global_hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []

    def make_eth(src_mac, dst_mac, ethertype=0x0800):
        smac = bytes.fromhex(src_mac.replace(':', ''))
        dmac = bytes.fromhex(dst_mac.replace(':', ''))
        return dmac + smac + struct.pack('>H', ethertype)

    def make_ip(src_ip, dst_ip, proto, payload_len):
        ver_ihl = (4 << 4) | 5
        total_len = 20 + payload_len
        sip = socket.inet_aton(src_ip)
        dip = socket.inet_aton(dst_ip)
        return struct.pack('>BBHHHBBH4s4s',
                           ver_ihl, 0, total_len, 54321, 0x4000, 64, proto, 0, sip, dip)

    def make_tcp(sport, dport, seq, ack, flags, window=65535, payload=b''):
        data_offset = (5 << 4)
        tcp_hdr = struct.pack('>HHIIBBHHH',
                              sport, dport, seq, ack, data_offset, flags, window, 0, 0)
        return tcp_hdr + payload

    def make_udp(sport, dport, payload=b''):
        length = 8 + len(payload)
        return struct.pack('>HHHH', sport, dport, length, 0) + payload

    def make_icmp(icmp_type, icmp_code, payload=b''):
        return struct.pack('>BBHI', icmp_type, icmp_code, 0, 0) + payload

    base_time = 1700000000

    # 1. TCP 3-way handshake (from synopsis!)
    # SYN
    p1 = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
         make_ip("192.168.1.100", "142.250.190.78", 6, 20) + \
         make_tcp(54321, 443, 1000, 0, 0x02) # SYN
    packets.append((base_time, 100000, p1))

    # SYN-ACK
    p2 = make_eth("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55") + \
         make_ip("142.250.190.78", "192.168.1.100", 6, 20) + \
         make_tcp(443, 54321, 5000, 1001, 0x12) # SYN-ACK
    packets.append((base_time, 250000, p2))

    # ACK
    p3 = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
         make_ip("192.168.1.100", "142.250.190.78", 6, 20) + \
         make_tcp(54321, 443, 1001, 5001, 0x10) # ACK
    packets.append((base_time + 1, 10000, p3))

    # 2. HTTP GET request and Response
    http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p4 = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
         make_ip("192.168.1.100", "93.184.216.34", 6, 20 + len(http_req)) + \
         make_tcp(51234, 80, 2000, 1, 0x18, payload=http_req) # PSH-ACK
    packets.append((base_time + 1, 500000, p4))

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello NetSnoop</h1>"
    p5 = make_eth("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55") + \
         make_ip("93.184.216.34", "192.168.1.100", 6, 20 + len(http_resp)) + \
         make_tcp(80, 51234, 1, 2000 + len(http_req), 0x18, payload=http_resp)
    packets.append((base_time + 1, 750000, p5))

    # 3. DNS Query (UDP port 53)
    dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    p6 = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
         make_ip("192.168.1.100", "8.8.8.8", 17, 8 + len(dns_query)) + \
         make_udp(49152, 53, payload=dns_query)
    packets.append((base_time + 2, 100000, p6))

    # 4. ICMP Ping Request & Reply
    p7 = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
         make_ip("192.168.1.100", "8.8.8.8", 1, 8 + 32) + \
         make_icmp(8, 0, payload=b"abcdefghijklmnopqrstuvwabcdefghi")
    packets.append((base_time + 2, 300000, p7))

    p8 = make_eth("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55") + \
         make_ip("8.8.8.8", "192.168.1.100", 1, 8 + 32) + \
         make_icmp(0, 0, payload=b"abcdefghijklmnopqrstuvwabcdefghi")
    packets.append((base_time + 2, 340000, p8))

    # 5. Simulated Port Scan (reaching ports 21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 8080)
    for i, port in enumerate([21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 8080, 8443]):
        scan_pkt = make_eth("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF") + \
                   make_ip("10.0.0.99", "192.168.1.1", 6, 20) + \
                   make_tcp(40000 + i, port, 100 + i, 0, 0x02) # SYN scan
        packets.append((base_time + 3, i * 20000, scan_pkt))

    with open(filename, 'wb') as f:
        f.write(global_hdr)
        for sec, usec, data in packets:
            l = len(data)
            rec_hdr = struct.pack('<IIII', sec, usec, l, l)
            f.write(rec_hdr)
            f.write(data)

    print(f"Generated {len(packets)} test packets into {filename}")

if __name__ == '__main__':
    write_pcap('samples/sample_traffic.pcap')
