#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "types.h"
#include "capture.h"
#include "parser.h"
#include "filter.h"
#include "display.h"
#include "stats.h"
#include "detector.h"
#include "console.h"

static volatile sig_atomic_t g_stop_requested = 0;
static PacketStats g_stats;
static PacketFilter g_filter;
static FILE *g_log_fp = NULL;
static int g_verbose = 0;
static uint64_t g_max_packets = 0;
static uint64_t g_matched_packets = 0;

static void signal_handler(int signum) {
    (void)signum;
    g_stop_requested = 1;
    capture_stop();
}

static void packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer) {
    (void)user;
    if (g_stop_requested) return;

    ParsedPacket pkt;
    if (parse_packet(header, buffer, &pkt) != 0) {
        return;
    }

    if (!filter_match(&g_filter, &pkt)) {
        return;
    }

    g_matched_packets++;
    stats_update(&g_stats, &pkt);
    display_packet(&pkt, g_log_fp, g_verbose);
    detector_inspect(&pkt, g_log_fp);

    /* Show periodic statistics milestone every 20 matching packets */
    if (g_matched_packets % 20 == 0) {
        stats_print_running(&g_stats);
    }

    if (g_max_packets > 0 && g_matched_packets >= g_max_packets) {
        printf("\n[*] Reached packet limit (%lu packets). Stopping...\n", (unsigned long)g_max_packets);
        capture_stop();
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        console_run();
        return 0;
    }

    char device[128] = {0};
    char pcap_file[256] = {0};
    char log_file[256] = {0};
    int opt;

    filter_init(&g_filter);
    stats_init(&g_stats);
    detector_init();

    while ((opt = getopt(argc, argv, "i:r:p:P:s:d:c:l:vLCh")) != -1) {
        switch (opt) {
            case 'C':
                console_run();
                return 0;
            case 'i':
                snprintf(device, sizeof(device), "%s", optarg);
                break;
            case 'r':
                snprintf(pcap_file, sizeof(pcap_file), "%s", optarg);
                break;
            case 'p':
                if (filter_set_protocol(&g_filter, optarg) != 0) {
                    fprintf(stderr, "[!] Invalid protocol filter: %s\n", optarg);
                    fprintf(stderr, "    Supported: ALL, TCP, UDP, ICMP, HTTP, DNS\n");
                    return 1;
                }
                break;
            case 'P':
                filter_set_port(&g_filter, (uint16_t)atoi(optarg));
                break;
            case 's':
                filter_set_src_ip(&g_filter, optarg);
                break;
            case 'd':
                filter_set_dest_ip(&g_filter, optarg);
                break;
            case 'c':
                g_max_packets = (uint64_t)strtoull(optarg, NULL, 10);
                break;
            case 'l':
                snprintf(log_file, sizeof(log_file), "%s", optarg);
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'L':
                return capture_list_devices();
            case 'h':
                display_help(argv[0]);
                return 0;
            default:
                display_help(argv[0]);
                return 1;
        }
    }

    display_banner();

    /* Setup signal handlers for graceful exit */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Open log file if requested */
    if (log_file[0] != '\0') {
        g_log_fp = fopen(log_file, "w");
        if (!g_log_fp) {
            perror("[!] Warning: Could not open log file");
        } else {
            printf("[*] Logging packet data to: %s\n", log_file);
        }
    }

    /* Initialize capture source */
    if (pcap_file[0] != '\0') {
        printf("[*] Reading from PCAP file: %s\n", pcap_file);
        if (capture_open_file(pcap_file) != 0) {
            if (g_log_fp) fclose(g_log_fp);
            return 1;
        }
    } else {
        printf("[*] Initializing live capture on interface: %s\n",
               device[0] ? device : "(default active)");
        if (capture_init(device[0] ? device : NULL, SNAP_LEN, PROMISC_MODE, TIMEOUT_MS) != 0) {
            if (g_log_fp) fclose(g_log_fp);
            return 1;
        }
    }

    printf("NetSnoop v1.0 – Starting capture...\n");
    printf("Filter: proto=%s, port=%u", g_filter.protocol, g_filter.port);
    if (g_filter.src_ip[0])  printf(", src=%s", g_filter.src_ip);
    if (g_filter.dest_ip[0]) printf(", dst=%s", g_filter.dest_ip);
    printf("\nPress Ctrl+C to stop.\n\n");

    /* Main capture loop */
    capture_start(packet_callback, NULL);

    /* Print final statistics */
    stats_print(&g_stats, g_log_fp);

    /* Clean up resources */
    if (g_log_fp) {
        fclose(g_log_fp);
        g_log_fp = NULL;
    }
    detector_cleanup();
    capture_cleanup();

    return 0;
}
