#ifndef NETSNOOP_DISPLAY_H
#define NETSNOOP_DISPLAY_H

#include "types.h"

/* Prints project banner and version info */
void display_banner(void);

/* Displays usage and command line options */
void display_help(const char *prog_name);

/* Formats and prints a single parsed packet */
void display_packet(const ParsedPacket *pkt);

#endif /* NETSNOOP_DISPLAY_H */
