#ifndef NETSNOOP_DISPLAY_H
#define NETSNOOP_DISPLAY_H

#include <stdio.h>
#include "types.h"

/* Prints project banner and version info */
void display_banner(void);

/* Displays usage and command line options */
void display_help(const char *prog_name);

/* Formats and prints a single parsed packet */
void display_packet(const ParsedPacket *pkt, FILE *log_fp, int verbose);

/* Displays packet payload in hex/ASCII dump format */
void display_payload(const uint8_t *data, uint32_t len, FILE *log_fp);

#endif /* NETSNOOP_DISPLAY_H */
