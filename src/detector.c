#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "detector.h"

#define HASH_SIZE 127
#define MAX_TRACK_PORTS 32
#define SYN_FLOOD_THRESHOLD 30
#define PORT_SCAN_THRESHOLD 10

typedef struct IPTrackerNode {
    uint32_t ip;
    char ip_str[16];
    uint32_t syn_count;
    uint32_t total_packets;
    time_t first_seen;
    time_t last_seen;
    uint16_t contacted_ports[MAX_TRACK_PORTS];
    int port_count;
    int syn_alert_fired;
    int scan_alert_fired;
    struct IPTrackerNode *next;
} IPTrackerNode;

static IPTrackerNode *g_hash_table[HASH_SIZE] = {NULL};

static unsigned int hash_ip(uint32_t ip) {
    return (unsigned int)(ip % HASH_SIZE);
}

void detector_init(void) {
    for (int i = 0; i < HASH_SIZE; i++) {
        g_hash_table[i] = NULL;
    }
}

static IPTrackerNode *get_or_create_node(uint32_t ip, const char *ip_str, time_t now) {
    unsigned int idx = hash_ip(ip);
    IPTrackerNode *curr = g_hash_table[idx];

    while (curr != NULL) {
        if (curr->ip == ip) {
            return curr;
        }
        curr = curr->next;
    }

    /* Allocate new tracking node */
    IPTrackerNode *node = (IPTrackerNode *)calloc(1, sizeof(IPTrackerNode));
    if (!node) return NULL;

    node->ip = ip;
    snprintf(node->ip_str, sizeof(node->ip_str), "%s", ip_str);
    node->first_seen = now;
    node->last_seen = now;
    node->next = g_hash_table[idx];
    g_hash_table[idx] = node;

    return node;
}

void detector_inspect(const ParsedPacket *pkt, FILE *log_fp) {
    if (!pkt || !pkt->is_ipv4) return;

    time_t now = pkt->timestamp.tv_sec ? pkt->timestamp.tv_sec : time(NULL);
    IPTrackerNode *node = get_or_create_node(pkt->src_ip_raw, pkt->src_ip_str, now);
    if (!node) return;

    node->total_packets++;
    node->last_seen = now;

    /* Check SYN Flood behavior (many SYN packets with no or few ACKs) */
    if (pkt->transport == PROTO_TCP && (pkt->tcp_flags & TCP_FLAG_SYN) && !(pkt->tcp_flags & TCP_FLAG_ACK)) {
        node->syn_count++;
        if (node->syn_count >= SYN_FLOOD_THRESHOLD && !node->syn_alert_fired) {
            node->syn_alert_fired = 1;
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "[!] SECURITY ALERT: Possible SYN Flood from %s (%u SYN packets)",
                     node->ip_str, node->syn_count);
            printf("\033[1;31m%s\033[0m\n", msg);
            if (log_fp) fprintf(log_fp, "%s\n", msg);
        }
    }

    /* Check Port Scanning behavior (reaching many different destination ports) */
    if (pkt->transport == PROTO_TCP || pkt->transport == PROTO_UDP) {
        uint16_t dport = pkt->dest_port;
        int found = 0;
        for (int i = 0; i < node->port_count; i++) {
            if (node->contacted_ports[i] == dport) {
                found = 1;
                break;
            }
        }
        if (!found && node->port_count < MAX_TRACK_PORTS) {
            node->contacted_ports[node->port_count++] = dport;
            if (node->port_count >= PORT_SCAN_THRESHOLD && !node->scan_alert_fired) {
                node->scan_alert_fired = 1;
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "[!] SECURITY ALERT: Possible Port Scan from %s (> %d unique ports queried)",
                         node->ip_str, PORT_SCAN_THRESHOLD);
                printf("\033[1;31m%s\033[0m\n", msg);
                if (log_fp) fprintf(log_fp, "%s\n", msg);
            }
        }
    }
}

void detector_cleanup(void) {
    for (int i = 0; i < HASH_SIZE; i++) {
        IPTrackerNode *curr = g_hash_table[i];
        while (curr != NULL) {
            IPTrackerNode *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
        g_hash_table[i] = NULL;
    }
}
