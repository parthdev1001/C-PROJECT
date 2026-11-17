#ifndef NETSNOOP_PARSER_H
#define NETSNOOP_PARSER_H

#include <pcap.h>
#include "types.h"

/* Top-level packet parser */
int parse_packet(const struct pcap_pkthdr *header, const u_char *buffer, ParsedPacket *pkt);

/* Protocol-specific parsers */
int parse_ethernet(const u_char *buffer, int size, ParsedPacket *pkt);
int parse_ip(const u_char *buffer, int size, ParsedPacket *pkt);
int parse_tcp(const u_char *buffer, int size, ParsedPacket *pkt);
int parse_udp(const u_char *buffer, int size, ParsedPacket *pkt);
int parse_icmp(const u_char *buffer, int size, ParsedPacket *pkt);

#endif /* NETSNOOP_PARSER_H */
