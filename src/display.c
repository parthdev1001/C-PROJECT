#include <stdio.h>
#include <time.h>
#include "display.h"

void display_banner(void) {
    printf("===================================================\n");
    printf("  NetSnoop - Simple Packet Sniffer in C\n");
    printf("  Data Structures Using C | MCA Semester 1\n");
    printf("===================================================\n");
}

void display_help(const char *prog_name) {
    display_banner();
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to capture from (default: auto)\n");
    printf("  -r <file.pcap>   Read and analyze offline PCAP file\n");
    printf("  -c <count>       Stop after this many packets\n");
    printf("  -L               List available network interfaces and exit\n");
    printf("  -h               Show this help message\n\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0\n", prog_name);
    printf("  %s -r samples/sample_traffic.pcap\n\n", prog_name);
}

void display_packet(const ParsedPacket *pkt) {
    if (!pkt) return;

    struct tm *tm_info = localtime(&pkt->timestamp.tv_sec);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    if (pkt->is_ipv4) {
        if (pkt->transport == PROTO_TCP) {
            printf("[%s] TCP  %s:%u -> %s:%u  %s  (%u bytes)\n", time_str,
                     pkt->src_ip_str, pkt->src_port,
                     pkt->dest_ip_str, pkt->dest_port,
                     pkt->tcp_flags_str, pkt->wirelen);
        } else if (pkt->transport == PROTO_UDP) {
            printf("[%s] UDP  %s:%u -> %s:%u  (%u bytes)\n", time_str,
                     pkt->src_ip_str, pkt->src_port,
                     pkt->dest_ip_str, pkt->dest_port,
                     pkt->wirelen);
        } else if (pkt->transport == PROTO_ICMP) {
            printf("[%s] ICMP %s -> %s  %s  (%u bytes)\n", time_str,
                     pkt->src_ip_str, pkt->dest_ip_str,
                     pkt->icmp_type_str ? pkt->icmp_type_str : "ICMP",
                     pkt->wirelen);
        } else {
            printf("[%s] IPv4 protocol %u  %s -> %s  (%u bytes)\n", time_str,
                     pkt->ip_protocol,
                     pkt->src_ip_str, pkt->dest_ip_str,
                     pkt->wirelen);
        }
    } else {
        printf("[%s] Ethernet %s -> %s  Type=0x%04X  (%u bytes)\n", time_str,
                 pkt->src_mac_str, pkt->dest_mac_str,
                 pkt->ethertype, pkt->wirelen);
    }
}
