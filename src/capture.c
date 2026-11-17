#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "capture.h"

static pcap_t *g_pcap_handle = NULL;
static char g_source_name[256] = "none";
static char g_errbuf[PCAP_ERRBUF_SIZE] = {0};

int capture_init(const char *device_name, int snaplen, int promisc, int to_ms) {
    pcap_if_t *alldevs = NULL;
    char selected_dev[128] = {0};

    if (device_name == NULL || strlen(device_name) == 0) {
        if (pcap_findalldevs(&alldevs, g_errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "[!] Error finding default interface: %s\n", g_errbuf);
            return -1;
        }
        snprintf(selected_dev, sizeof(selected_dev), "%s", alldevs->name);
        pcap_freealldevs(alldevs);
    } else {
        snprintf(selected_dev, sizeof(selected_dev), "%s", device_name);
    }

    g_pcap_handle = pcap_open_live(selected_dev, snaplen, promisc, to_ms, g_errbuf);
    if (g_pcap_handle == NULL) {
        fprintf(stderr, "[!] Could not open device '%s': %s\n", selected_dev, g_errbuf);
        return -1;
    }

    /* Check link-layer type: warn if not standard Ethernet */
    int link_type = pcap_datalink(g_pcap_handle);
    if (link_type != DLT_EN10MB) {
        fprintf(stderr, "[!] Warning: Device '%s' link type is %d (expected DLT_EN10MB=1).\n",
                selected_dev, link_type);
    }

    snprintf(g_source_name, sizeof(g_source_name), "%s", selected_dev);
    return 0;
}

int capture_open_file(const char *pcap_path) {
    if (pcap_path == NULL) return -1;

    g_pcap_handle = pcap_open_offline(pcap_path, g_errbuf);
    if (g_pcap_handle == NULL) {
        fprintf(stderr, "[!] Failed to open PCAP file '%s': %s\n", pcap_path, g_errbuf);
        return -1;
    }

    snprintf(g_source_name, sizeof(g_source_name), "file:%s", pcap_path);
    return 0;
}

int capture_start(pcap_handler callback, u_char *user) {
    if (g_pcap_handle == NULL) {
        fprintf(stderr, "[!] Capture handle is not initialized.\n");
        return -1;
    }
    return pcap_loop(g_pcap_handle, 0, callback, user);
}

void capture_stop(void) {
    if (g_pcap_handle != NULL) {
        pcap_breakloop(g_pcap_handle);
    }
}

void capture_cleanup(void) {
    if (g_pcap_handle != NULL) {
        pcap_close(g_pcap_handle);
        g_pcap_handle = NULL;
    }
}

int capture_list_devices(void) {
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    int idx = 1;

    if (pcap_findalldevs(&alldevs, g_errbuf) == -1) {
        fprintf(stderr, "[!] Error finding network devices: %s\n", g_errbuf);
        return -1;
    }

    printf("\n=== Available Network Interfaces ===\n");
    for (dev = alldevs; dev != NULL; dev = dev->next, idx++) {
        printf(" [%2d] %-15s", idx, dev->name);
        if (dev->description) {
            printf(" (%s)", dev->description);
        }

        /* Show IPv4 addresses assigned */
        for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                char ip_buf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf))) {
                    printf(" [IPv4: %s]", ip_buf);
                }
            }
        }
        printf("\n");
    }
    printf("====================================\n\n");

    pcap_freealldevs(alldevs);
    return 0;
}

const char *capture_get_source_name(void) {
    return g_source_name;
}
