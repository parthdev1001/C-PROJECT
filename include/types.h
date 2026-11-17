#ifndef NETSNOOP_TYPES_H
#define NETSNOOP_TYPES_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>

#define SNAP_LEN 65535
#define PROMISC_MODE 1
#define TIMEOUT_MS 1000

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL  6
#define IPPROTO_UDP_VAL  17

/* TCP flag bitmasks */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

/* Ethernet Header: 14 bytes */
typedef struct __attribute__((packed)) {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

/* IPv4 Header: 20 bytes minimum */
typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;          /* 4 bits version, 4 bits IHL */
    uint8_t  tos;              /* Type of Service */
    uint16_t total_length;     /* Total length (header + data) */
    uint16_t id;               /* Identification */
    uint16_t flags_fo;         /* 3 bits flags, 13 bits fragment offset */
    uint8_t  ttl;              /* Time to live */
    uint8_t  protocol;         /* Transport protocol */
    uint16_t checksum;         /* Header checksum */
    uint32_t src_ip;           /* Source IPv4 address */
    uint32_t dest_ip;          /* Destination IPv4 address */
} IPHeader;

/* TCP Header: 20 bytes minimum */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_res;  /* 4 bits data offset, 4 bits reserved */
    uint8_t  flags;            /* Control flags */
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

/* UDP Header: 8 bytes */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

/* ICMP Header: 4 bytes base + 4 bytes header data */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest_of_header;
} ICMPHeader;

typedef enum {
    PROTO_NONE = 0,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_OTHER
} TransportProto;

typedef enum {
    APP_NONE = 0,
    APP_HTTP,
    APP_HTTPS,
    APP_DNS,
    APP_OTHER
} AppProto;

/* Unified parsed representation */
typedef struct {
    struct timeval timestamp;
    uint32_t caplen;
    uint32_t wirelen;

    /* Ethernet */
    char src_mac_str[18];
    char dest_mac_str[18];
    uint16_t ethertype;

    /* IPv4 */
    int is_ipv4;
    char src_ip_str[16];
    char dest_ip_str[16];
    uint32_t src_ip_raw;
    uint32_t dest_ip_raw;
    uint8_t ip_version;
    uint8_t ip_ihl_bytes;
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint16_t ip_total_length;

    /* Transport */
    TransportProto transport;
    uint16_t src_port;
    uint16_t dest_port;

    /* TCP specific */
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_flags;
    char tcp_flags_str[32];
    uint16_t tcp_window;
    uint8_t tcp_header_len;

    /* UDP specific */
    uint16_t udp_length;

    /* ICMP specific */
    uint8_t icmp_type;
    uint8_t icmp_code;
    const char *icmp_type_str;

    /* Application layer inference */
    AppProto app_proto;
    const char *app_str;

    /* Payload */
    const uint8_t *payload;
    uint32_t payload_len;
} ParsedPacket;

/* Packet filter configuration */
typedef struct {
    int active;
    char protocol[16];   /* "ALL", "TCP", "UDP", "ICMP", "HTTP", "DNS" */
    uint16_t port;       /* 0 = any */
    char src_ip[16];     /* "" = any */
    char dest_ip[16];    /* "" = any */
} PacketFilter;

/* Statistics accumulator */
typedef struct {
    struct timeval start_time;
    struct timeval last_time;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t other_count;
    uint64_t http_count;
    uint64_t https_count;
    uint64_t dns_count;
    uint64_t syn_count;
    uint64_t fin_count;
    uint64_t rst_count;
} PacketStats;

#endif /* NETSNOOP_TYPES_H */
