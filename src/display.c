#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "display.h"

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_RED     "\033[31m"

void display_banner(void) {
    printf(ANSI_CYAN ANSI_BOLD);
    printf("=================================================================\n");
    printf("  NetSnoop v1.0 - Real-Time Packet Sniffer & Protocol Analyzer   \n");
    printf("  Data Structures Using C | MCA Semester 1 (2026-2027)           \n");
    printf("=================================================================\n");
    printf(ANSI_RESET);
}

void display_help(const char *prog_name) {
    display_banner();
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to capture from (default: auto)\n");
    printf("  -r <file.pcap>   Read and analyze offline PCAP file\n");
    printf("  -p <protocol>    Filter protocol: ALL, TCP, UDP, ICMP, HTTP, DNS\n");
    printf("  -P <port>        Filter by port number (e.g., 80, 443, 53)\n");
    printf("  -s <source_ip>   Filter by source IPv4 address\n");
    printf("  -d <dest_ip>     Filter by destination IPv4 address\n");
    printf("  -c <count>       Stop capture after <count> matching packets\n");
    printf("  -l <logfile>     Save captured packet summaries to log file\n");
    printf("  -v               Verbose output (header details & payload dump)\n");
    printf("  -C               Launch interactive management console\n");
    printf("  -L               List available network interfaces and exit\n");
    printf("  -h               Show this help message\n\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0\n", prog_name);
    printf("  sudo %s -p TCP -P 443\n", prog_name);
    printf("  %s -r samples/traffic.pcap -p HTTP -v\n\n", prog_name);
}

void display_payload(const uint8_t *data, uint32_t len, FILE *log_fp) {
    if (!data || len == 0) return;

    uint32_t max_show = len > 128 ? 128 : len;
    char ascii_buf[17] = {0};

    printf("  Payload Dump (%u bytes%s):\n", len, len > 128 ? ", showing first 128" : "");
    if (log_fp) fprintf(log_fp, "  Payload Dump (%u bytes):\n", len);

    for (uint32_t i = 0; i < max_show; i++) {
        if (i % 16 == 0) {
            printf("    %04X  ", i);
            if (log_fp) fprintf(log_fp, "    %04X  ", i);
        }

        printf("%02X ", data[i]);
        if (log_fp) fprintf(log_fp, "%02X ", data[i]);
        ascii_buf[i % 16] = (isprint(data[i]) ? (char)data[i] : '.');

        if ((i + 1) % 16 == 0 || i + 1 == max_show) {
            /* Pad if line ended early */
            if ((i + 1) % 16 != 0) {
                int pad = 16 - ((i + 1) % 16);
                for (int p = 0; p < pad; p++) {
                    printf("   ");
                    if (log_fp) fprintf(log_fp, "   ");
                }
                ascii_buf[(i + 1) % 16] = '\0';
            }
            printf(" |%s|\n", ascii_buf);
            if (log_fp) fprintf(log_fp, " |%s|\n", ascii_buf);
            memset(ascii_buf, 0, sizeof(ascii_buf));
        }
    }
}

void display_packet(const ParsedPacket *pkt, FILE *log_fp, int verbose) {
    if (!pkt) return;

    struct tm *tm_info = localtime(&pkt->timestamp.tv_sec);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    char line_buf[512] = {0};

    if (pkt->is_ipv4) {
        if (pkt->transport == PROTO_TCP) {
            snprintf(line_buf, sizeof(line_buf),
                     "[%s] TCP %s:%u \xe2\x86\x92 %s:%u %s Len=%u",
                     time_str,
                     pkt->src_ip_str, pkt->src_port,
                     pkt->dest_ip_str, pkt->dest_port,
                     pkt->tcp_flags_str, pkt->wirelen);
            printf(ANSI_GREEN "%s" ANSI_RESET "\n", line_buf);
        } else if (pkt->transport == PROTO_UDP) {
            const char *tag = pkt->app_str ? pkt->app_str : "UDP";
            snprintf(line_buf, sizeof(line_buf),
                     "[%s] UDP %s:%u \xe2\x86\x92 %s:%u [%s] Len=%u",
                     time_str,
                     pkt->src_ip_str, pkt->src_port,
                     pkt->dest_ip_str, pkt->dest_port,
                     tag, pkt->wirelen);
            printf(ANSI_BLUE "%s" ANSI_RESET "\n", line_buf);
        } else if (pkt->transport == PROTO_ICMP) {
            snprintf(line_buf, sizeof(line_buf),
                     "[%s] ICMP %s \xe2\x86\x92 %s [%s] Len=%u",
                     time_str,
                     pkt->src_ip_str, pkt->dest_ip_str,
                     pkt->icmp_type_str ? pkt->icmp_type_str : "ICMP",
                     pkt->wirelen);
            printf(ANSI_YELLOW "%s" ANSI_RESET "\n", line_buf);
        } else {
            snprintf(line_buf, sizeof(line_buf),
                     "[%s] IPv4 (Proto %u) %s \xe2\x86\x92 %s Len=%u",
                     time_str, pkt->ip_protocol,
                     pkt->src_ip_str, pkt->dest_ip_str,
                     pkt->wirelen);
            printf("%s\n", line_buf);
        }
    } else {
        snprintf(line_buf, sizeof(line_buf),
                 "[%s] ETH %s \xe2\x86\x92 %s Type=0x%04X Len=%u",
                 time_str, pkt->src_mac_str, pkt->dest_mac_str,
                 pkt->ethertype, pkt->wirelen);
        printf("%s\n", line_buf);
    }

    if (log_fp) {
        fprintf(log_fp, "%s\n", line_buf);
    }

    if (verbose) {
        printf("  Detail: MAC [%s -> %s] TTL=%u\n",
               pkt->src_mac_str, pkt->dest_mac_str, pkt->ip_ttl);
        if (pkt->transport == PROTO_TCP) {
            printf("  TCP: Seq=0x%08X Ack=0x%08X Win=%u HdrLen=%u\n",
                   pkt->tcp_seq, pkt->tcp_ack, pkt->tcp_window, pkt->tcp_header_len);
        }
        if (pkt->payload_len > 0) {
            display_payload(pkt->payload, pkt->payload_len, log_fp);
        }
    }
}
