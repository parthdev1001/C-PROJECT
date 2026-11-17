#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "types.h"
#include "parser.h"

static void test_ethernet_and_ip_tcp(void) {
    /* Construct a synthetic Ethernet + IPv4 + TCP packet */
    uint8_t packet[74];
    memset(packet, 0, sizeof(packet));

    /* Ethernet Header (14 bytes) */
    EthernetHeader *eth = (EthernetHeader *)packet;
    eth->dest_mac[0] = 0x00; eth->dest_mac[1] = 0x11; eth->dest_mac[2] = 0x22;
    eth->dest_mac[3] = 0x33; eth->dest_mac[4] = 0x44; eth->dest_mac[5] = 0x55;
    eth->src_mac[0] = 0xAA;  eth->src_mac[1] = 0xBB;  eth->src_mac[2] = 0xCC;
    eth->src_mac[3] = 0xDD;  eth->src_mac[4] = 0xEE;  eth->src_mac[5] = 0xFF;
    eth->ethertype = htons(ETHERTYPE_IP);

    /* IPv4 Header (20 bytes) */
    IPHeader *ip = (IPHeader *)(packet + 14);
    ip->ver_ihl = (4 << 4) | 5; /* IPv4, IHL = 5 (20 bytes) */
    ip->tos = 0;
    ip->total_length = htons(60);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP_VAL;
    inet_pton(AF_INET, "192.168.1.100", &ip->src_ip);
    inet_pton(AF_INET, "142.250.190.78", &ip->dest_ip);

    /* TCP Header (20 bytes) */
    TCPHeader *tcp = (TCPHeader *)(packet + 14 + 20);
    tcp->src_port = htons(54321);
    tcp->dest_port = htons(443);
    tcp->seq_num = htonl(100000);
    tcp->ack_num = htonl(0);
    tcp->data_offset_res = (5 << 4); /* 5 * 4 = 20 bytes */
    tcp->flags = TCP_FLAG_SYN;
    tcp->window_size = htons(65535);

    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = 1700000000;
    hdr.ts.tv_usec = 0;
    hdr.caplen = 54;
    hdr.len = 60;

    ParsedPacket pkt;
    int res = parse_packet(&hdr, packet, &pkt);
    assert(res == 0);

    /* Verify Ethernet */
    assert(strcmp(pkt.dest_mac_str, "00:11:22:33:44:55") == 0);
    assert(strcmp(pkt.src_mac_str, "AA:BB:CC:DD:EE:FF") == 0);
    assert(pkt.ethertype == ETHERTYPE_IP);

    /* Verify IP */
    assert(pkt.is_ipv4 == 1);
    assert(pkt.ip_version == 4);
    assert(pkt.ip_ihl_bytes == 20);
    assert(pkt.ip_ttl == 64);
    assert(strcmp(pkt.src_ip_str, "192.168.1.100") == 0);
    assert(strcmp(pkt.dest_ip_str, "142.250.190.78") == 0);

    /* Verify TCP */
    assert(pkt.transport == PROTO_TCP);
    assert(pkt.src_port == 54321);
    assert(pkt.dest_port == 443);
    assert(pkt.tcp_seq == 100000);
    assert(pkt.tcp_flags == TCP_FLAG_SYN);
    assert(strcmp(pkt.tcp_flags_str, "[SYN]") == 0);

    printf("  [PASS] Ethernet + IPv4 + TCP parsing test passed.\n");
}

static void test_udp(void) {
    uint8_t packet[42];
    memset(packet, 0, sizeof(packet));

    EthernetHeader *eth = (EthernetHeader *)packet;
    eth->ethertype = htons(ETHERTYPE_IP);

    IPHeader *ip = (IPHeader *)(packet + 14);
    ip->ver_ihl = (4 << 4) | 5;
    ip->protocol = IPPROTO_UDP_VAL;
    inet_pton(AF_INET, "10.0.0.5", &ip->src_ip);
    inet_pton(AF_INET, "8.8.8.8", &ip->dest_ip);

    UDPHeader *udp = (UDPHeader *)(packet + 34);
    udp->src_port = htons(53535);
    udp->dest_port = htons(53);
    udp->length = htons(8);

    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = 1700000001;
    hdr.ts.tv_usec = 1000;
    hdr.caplen = 42;
    hdr.len = 42;

    ParsedPacket pkt;
    assert(parse_packet(&hdr, packet, &pkt) == 0);
    assert(pkt.transport == PROTO_UDP);
    assert(pkt.src_port == 53535);
    assert(pkt.dest_port == 53);
    printf("  [PASS] UDP parsing test passed.\n");
}

static void test_icmp(void) {
    uint8_t packet[42];
    memset(packet, 0, sizeof(packet));

    EthernetHeader *eth = (EthernetHeader *)packet;
    eth->ethertype = htons(ETHERTYPE_IP);

    IPHeader *ip = (IPHeader *)(packet + 14);
    ip->ver_ihl = (4 << 4) | 5;
    ip->protocol = IPPROTO_ICMP_VAL;
    inet_pton(AF_INET, "192.168.1.1", &ip->src_ip);
    inet_pton(AF_INET, "192.168.1.254", &ip->dest_ip);

    ICMPHeader *icmp = (ICMPHeader *)(packet + 34);
    icmp->type = 8; /* Echo Request */
    icmp->code = 0;

    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = 1700000002;
    hdr.ts.tv_usec = 2000;
    hdr.caplen = 42;
    hdr.len = 64;

    ParsedPacket pkt;
    assert(parse_packet(&hdr, packet, &pkt) == 0);
    assert(pkt.transport == PROTO_ICMP);
    assert(pkt.icmp_type == 8);
    assert(strcmp(pkt.icmp_type_str, "Echo Request") == 0);

    printf("  [PASS] ICMP parsing test passed.\n");
}

int main(void) {
    printf("\n=== Running NetSnoop Unit Tests ===\n");
    test_ethernet_and_ip_tcp();
    test_udp();
    test_icmp();
    printf("=== All NetSnoop Unit Tests Passed Successfully! ===\n\n");
    return 0;
}
