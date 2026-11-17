#ifndef NETSNOOP_DETECTOR_H
#define NETSNOOP_DETECTOR_H

#include "types.h"

/* Initialize the anomaly detection subsystem */
void detector_init(void);

/* Inspect a packet for suspicious patterns (SYN flood, port scans) */
void detector_inspect(const ParsedPacket *pkt, FILE *log_fp);

/* Free allocated state */
void detector_cleanup(void);

#endif /* NETSNOOP_DETECTOR_H */
