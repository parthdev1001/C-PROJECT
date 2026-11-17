#ifndef NETSNOOP_STATS_H
#define NETSNOOP_STATS_H

#include <stdio.h>
#include "types.h"

/* Initialize statistics structure */
void stats_init(PacketStats *stats);

/* Update statistics with a parsed packet */
void stats_update(PacketStats *stats, const ParsedPacket *pkt);

/* Print current running statistics summary */
void stats_print_running(const PacketStats *stats);

/* Print final detailed report */
void stats_print(const PacketStats *stats, FILE *out);

/* Calculate packets per second */
double stats_get_pps(const PacketStats *stats);

#endif /* NETSNOOP_STATS_H */
