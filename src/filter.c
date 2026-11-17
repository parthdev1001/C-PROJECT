#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "filter.h"

void filter_init(PacketFilter *filter) {
    if (!filter) return;
    memset(filter, 0, sizeof(PacketFilter));
    filter->active = 0;
    strncpy(filter->protocol, "ALL", sizeof(filter->protocol) - 1);
}

int filter_set_protocol(PacketFilter *filter, const char *proto) {
    if (!filter || !proto) return -1;

    char upper[16] = {0};
    size_t len = strlen(proto);
    if (len >= sizeof(upper)) len = sizeof(upper) - 1;

    for (size_t i = 0; i < len; i++) {
        upper[i] = (char)toupper((unsigned char)proto[i]);
    }

    if (strcmp(upper, "ALL") != 0 &&
        strcmp(upper, "TCP") != 0 &&
        strcmp(upper, "UDP") != 0 &&
        strcmp(upper, "ICMP") != 0 &&
        strcmp(upper, "HTTP") != 0 &&
        strcmp(upper, "DNS") != 0) {
        return -1;
    }

    snprintf(filter->protocol, sizeof(filter->protocol), "%s", upper);
    filter->active = 1;
    return 0;
}

void filter_set_port(PacketFilter *filter, uint16_t port) {
    if (!filter) return;
    filter->port = port;
    if (port > 0) filter->active = 1;
}

void filter_set_src_ip(PacketFilter *filter, const char *ip_str) {
    if (!filter || !ip_str) return;
    snprintf(filter->src_ip, sizeof(filter->src_ip), "%s", ip_str);
    if (strlen(ip_str) > 0) filter->active = 1;
}

void filter_set_dest_ip(PacketFilter *filter, const char *ip_str) {
    if (!filter || !ip_str) return;
    snprintf(filter->dest_ip, sizeof(filter->dest_ip), "%s", ip_str);
    if (strlen(ip_str) > 0) filter->active = 1;
}

int filter_match(const PacketFilter *filter, const ParsedPacket *pkt) {
    if (!filter || !filter->active) return 1;
    if (!pkt) return 0;

    /* Protocol check */
    if (strcmp(filter->protocol, "ALL") != 0) {
        if (strcmp(filter->protocol, "TCP") == 0) {
            if (pkt->transport != PROTO_TCP) return 0;
        } else if (strcmp(filter->protocol, "UDP") == 0) {
            if (pkt->transport != PROTO_UDP) return 0;
        } else if (strcmp(filter->protocol, "ICMP") == 0) {
            if (pkt->transport != PROTO_ICMP) return 0;
        } else if (strcmp(filter->protocol, "HTTP") == 0) {
            if (pkt->app_proto != APP_HTTP &&
                pkt->src_port != 80 && pkt->dest_port != 80 &&
                pkt->src_port != 8080 && pkt->dest_port != 8080) {
                return 0;
            }
        } else if (strcmp(filter->protocol, "DNS") == 0) {
            if (pkt->app_proto != APP_DNS &&
                pkt->src_port != 53 && pkt->dest_port != 53) {
                return 0;
            }
        }
    }

    /* Port check */
    if (filter->port > 0) {
        if (pkt->src_port != filter->port && pkt->dest_port != filter->port) {
            return 0;
        }
    }

    /* Source IP check */
    if (filter->src_ip[0] != '\0') {
        if (strcmp(pkt->src_ip_str, filter->src_ip) != 0) {
            return 0;
        }
    }

    /* Destination IP check */
    if (filter->dest_ip[0] != '\0') {
        if (strcmp(pkt->dest_ip_str, filter->dest_ip) != 0) {
            return 0;
        }
    }

    return 1;
}
