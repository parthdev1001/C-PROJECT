#ifndef NETSNOOP_CAPTURE_H
#define NETSNOOP_CAPTURE_H

#include <pcap.h>
#include "types.h"

/* Initialize live capture on the specified device */
int capture_init(const char *device_name, int snaplen, int promisc, int to_ms);

/* Open an offline PCAP file instead of a live interface */
int capture_open_file(const char *pcap_path);

/* Start capturing packets; invokes callback on each packet */
int capture_start(pcap_handler callback, u_char *user);

/* Request the capture loop to stop cleanly */
void capture_stop(void);

/* Clean up pcap handles */
void capture_cleanup(void);

/* List available network interfaces on the system */
int capture_list_devices(void);

/* Get the name of the currently active device or file */
const char *capture_get_source_name(void);

#endif /* NETSNOOP_CAPTURE_H */
