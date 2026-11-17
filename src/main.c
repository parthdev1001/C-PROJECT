#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "types.h"
#include "capture.h"
#include "parser.h"
#include "display.h"

/* These counters are kept here so the whole program is easy to follow. */
static volatile sig_atomic_t stop_requested = 0;
static unsigned long packet_count = 0;
static unsigned long tcp_count = 0;
static unsigned long udp_count = 0;
static unsigned long icmp_count = 0;
static unsigned long other_count = 0;
static unsigned long max_packets = 0;

static void stop_capture(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
    capture_stop();
}

static void packet_callback(u_char *user, const struct pcap_pkthdr *header,
                            const u_char *buffer) {
    (void)user;
    ParsedPacket packet;

    if (stop_requested || parse_packet(header, buffer, &packet) != 0) {
        return;
    }

    packet_count++;
    display_packet(&packet);

    switch (packet.transport) {
        case PROTO_TCP:  tcp_count++; break;
        case PROTO_UDP:  udp_count++; break;
        case PROTO_ICMP: icmp_count++; break;
        default:         other_count++; break;
    }

    if (max_packets > 0 && packet_count >= max_packets) {
        capture_stop();
    }
}

static void print_summary(void) {
    printf("\n--- Capture Summary ---\n");
    printf("Packets: %lu | TCP: %lu | UDP: %lu | ICMP: %lu | Other: %lu\n",
           packet_count, tcp_count, udp_count, icmp_count, other_count);
}

int main(int argc, char *argv[]) {
    char device[128] = {0};
    char pcap_file[256] = {0};
    int option;

    while ((option = getopt(argc, argv, "i:r:c:Lh")) != -1) {
        switch (option) {
            case 'i':
                snprintf(device, sizeof(device), "%s", optarg);
                break;
            case 'r':
                snprintf(pcap_file, sizeof(pcap_file), "%s", optarg);
                break;
            case 'c':
                max_packets = strtoul(optarg, NULL, 10);
                break;
            case 'L':
                return capture_list_devices() == 0 ? 0 : 1;
            case 'h':
                display_help(argv[0]);
                return 0;
            default:
                display_help(argv[0]);
                return 1;
        }
    }

    if (device[0] != '\0' && pcap_file[0] != '\0') {
        fprintf(stderr, "Use either -i for live capture or -r for a PCAP file.\n");
        return 1;
    }

    signal(SIGINT, stop_capture);
    display_banner();

    if (pcap_file[0] != '\0') {
        printf("Reading PCAP file: %s\n\n", pcap_file);
        if (capture_open_file(pcap_file) != 0) {
            return 1;
        }
    } else {
        printf("Capturing live traffic from: %s\nPress Ctrl+C to stop.\n\n",
               device[0] ? device : "first available interface");
        if (capture_init(device[0] ? device : NULL, SNAP_LEN, PROMISC_MODE,
                         TIMEOUT_MS) != 0) {
            return 1;
        }
    }

    capture_start(packet_callback, NULL);
    print_summary();
    capture_cleanup();
    return 0;
}
