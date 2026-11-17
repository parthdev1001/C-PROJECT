#ifndef NETSNOOP_FILTER_H
#define NETSNOOP_FILTER_H

#include "types.h"

/* Initialize filter configuration */
void filter_init(PacketFilter *filter);

/* Set protocol filter ("ALL", "TCP", "UDP", "ICMP", "HTTP", "DNS") */
int filter_set_protocol(PacketFilter *filter, const char *proto);

/* Set port filter (0 means match any port) */
void filter_set_port(PacketFilter *filter, uint16_t port);

/* Set IP filter (matches either src or dest depending on rule) */
void filter_set_src_ip(PacketFilter *filter, const char *ip_str);
void filter_set_dest_ip(PacketFilter *filter, const char *ip_str);

/* Returns 1 if packet passes filter, 0 otherwise */
int filter_match(const PacketFilter *filter, const ParsedPacket *pkt);

#endif /* NETSNOOP_FILTER_H */
