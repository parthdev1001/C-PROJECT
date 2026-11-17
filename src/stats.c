#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "stats.h"

void stats_init(PacketStats *stats) {
    if (!stats) return;
    memset(stats, 0, sizeof(PacketStats));
    gettimeofday(&stats->start_time, NULL);
    stats->last_time = stats->start_time;
}

void stats_update(PacketStats *stats, const ParsedPacket *pkt) {
    if (!stats || !pkt) return;

    stats->total_packets++;
    stats->total_bytes += pkt->wirelen;
    stats->last_time = pkt->timestamp;

    switch (pkt->transport) {
        case PROTO_TCP:
            stats->tcp_count++;
            if (pkt->tcp_flags & TCP_FLAG_SYN) stats->syn_count++;
            if (pkt->tcp_flags & TCP_FLAG_FIN) stats->fin_count++;
            if (pkt->tcp_flags & TCP_FLAG_RST) stats->rst_count++;

            if (pkt->app_proto == APP_HTTP)  stats->http_count++;
            if (pkt->app_proto == APP_HTTPS) stats->https_count++;
            if (pkt->app_proto == APP_DNS)   stats->dns_count++;
            break;

        case PROTO_UDP:
            stats->udp_count++;
            if (pkt->app_proto == APP_DNS) stats->dns_count++;
            break;

        case PROTO_ICMP:
            stats->icmp_count++;
            break;

        default:
            stats->other_count++;
            break;
    }
}

double stats_get_pps(const PacketStats *stats) {
    if (!stats || stats->total_packets == 0) return 0.0;

    double elapsed = (double)(stats->last_time.tv_sec - stats->start_time.tv_sec) +
                     (double)(stats->last_time.tv_usec - stats->start_time.tv_usec) / 1000000.0;

    if (elapsed <= 0.0001) return (double)stats->total_packets;
    return (double)stats->total_packets / elapsed;
}

void stats_print_running(const PacketStats *stats) {
    if (!stats) return;
    printf("\n--- Running Statistics ---\n");
    printf("Total Packets: %lu | TCP: %lu | UDP: %lu | ICMP: %lu\n",
           (unsigned long)stats->total_packets,
           (unsigned long)stats->tcp_count,
           (unsigned long)stats->udp_count,
           (unsigned long)stats->icmp_count);
    printf("Packets/sec: %.1f\n", stats_get_pps(stats));
    printf("--------------------------\n\n");
}

void stats_print(const PacketStats *stats, FILE *out) {
    if (!stats) return;

    double pps = stats_get_pps(stats);
    double elapsed = (double)(stats->last_time.tv_sec - stats->start_time.tv_sec) +
                     (double)(stats->last_time.tv_usec - stats->start_time.tv_usec) / 1000000.0;
    if (elapsed < 0.001) elapsed = 0.001;

    double kb = (double)stats->total_bytes / 1024.0;
    double kbps = (elapsed > 0) ? (kb / elapsed) : 0.0;

    FILE *destinations[2] = { stdout, out };
    int count = (out && out != stdout) ? 2 : 1;

    for (int i = 0; i < count; i++) {
        FILE *f = destinations[i];
        if (!f) continue;

        fprintf(f, "\n");
        fprintf(f, "========================================================\n");
        fprintf(f, "               NetSnoop Final Statistics                \n");
        fprintf(f, "========================================================\n");
        fprintf(f, " Elapsed Time        : %.2f seconds\n", elapsed);
        fprintf(f, " Total Packets       : %lu\n", (unsigned long)stats->total_packets);
        fprintf(f, " Total Transferred   : %.2f KB (%lu bytes)\n", kb, (unsigned long)stats->total_bytes);
        fprintf(f, " Average Throughput  : %.2f KB/s (%.1f pkts/sec)\n", kbps, pps);
        fprintf(f, "--------------------------------------------------------\n");
        fprintf(f, " Protocol Breakdown:\n");
        fprintf(f, "   TCP Packets       : %lu (%.1f%%)\n",
                (unsigned long)stats->tcp_count,
                stats->total_packets ? (100.0 * stats->tcp_count / stats->total_packets) : 0.0);
        fprintf(f, "   UDP Packets       : %lu (%.1f%%)\n",
                (unsigned long)stats->udp_count,
                stats->total_packets ? (100.0 * stats->udp_count / stats->total_packets) : 0.0);
        fprintf(f, "   ICMP Packets      : %lu (%.1f%%)\n",
                (unsigned long)stats->icmp_count,
                stats->total_packets ? (100.0 * stats->icmp_count / stats->total_packets) : 0.0);
        fprintf(f, "   Other/ARP/ETH     : %lu (%.1f%%)\n",
                (unsigned long)stats->other_count,
                stats->total_packets ? (100.0 * stats->other_count / stats->total_packets) : 0.0);
        fprintf(f, "--------------------------------------------------------\n");
        fprintf(f, " Application / Flag Indicators:\n");
        fprintf(f, "   HTTP / HTTPS      : %lu / %lu\n",
                (unsigned long)stats->http_count, (unsigned long)stats->https_count);
        fprintf(f, "   DNS Requests/Resp : %lu\n", (unsigned long)stats->dns_count);
        fprintf(f, "   TCP SYN / FIN/RST : %lu / %lu\n",
                (unsigned long)stats->syn_count,
                (unsigned long)(stats->fin_count + stats->rst_count));
        fprintf(f, "========================================================\n\n");
    }
}
