#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "parser.h"

int parse_ethernet(const u_char *buffer, int size, ParsedPacket *pkt) {
    if (size < (int)sizeof(EthernetHeader)) return -1;

    const EthernetHeader *eth = (const EthernetHeader *)buffer;

    snprintf(pkt->dest_mac_str, sizeof(pkt->dest_mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
             eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);

    snprintf(pkt->src_mac_str, sizeof(pkt->src_mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
             eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);

    pkt->ethertype = ntohs(eth->ethertype);
    return sizeof(EthernetHeader);
}

int parse_ip(const u_char *buffer, int size, ParsedPacket *pkt) {
    if (size < (int)sizeof(IPHeader)) return -1;

    const IPHeader *ip = (const IPHeader *)buffer;

    /* Bitwise extraction of IPv4 version and header length */
    pkt->ip_version = (ip->ver_ihl >> 4) & 0x0F;
    uint8_t ihl_words = ip->ver_ihl & 0x0F;
    pkt->ip_ihl_bytes = (uint8_t)(ihl_words * 4);

    if (pkt->ip_version != 4 || pkt->ip_ihl_bytes < sizeof(IPHeader) || pkt->ip_ihl_bytes > size) {
        return -1;
    }

    pkt->ip_total_length = ntohs(ip->total_length);
    pkt->ip_ttl = ip->ttl;
    pkt->ip_protocol = ip->protocol;
    pkt->src_ip_raw = ip->src_ip;
    pkt->dest_ip_raw = ip->dest_ip;

    struct in_addr src_addr = { .s_addr = ip->src_ip };
    struct in_addr dst_addr = { .s_addr = ip->dest_ip };

    inet_ntop(AF_INET, &src_addr, pkt->src_ip_str, sizeof(pkt->src_ip_str));
    inet_ntop(AF_INET, &dst_addr, pkt->dest_ip_str, sizeof(pkt->dest_ip_str));

    pkt->is_ipv4 = 1;
    return pkt->ip_ihl_bytes;
}

static void format_tcp_flags(uint8_t flags, char *out, size_t out_len) {
    char temp[64] = {0};
    int count = 0;

    if (flags & TCP_FLAG_SYN) { strcat(temp, count++ ? "-SYN" : "SYN"); }
    if (flags & TCP_FLAG_ACK) { strcat(temp, count++ ? "-ACK" : "ACK"); }
    if (flags & TCP_FLAG_FIN) { strcat(temp, count++ ? "-FIN" : "FIN"); }
    if (flags & TCP_FLAG_RST) { strcat(temp, count++ ? "-RST" : "RST"); }
    if (flags & TCP_FLAG_PSH) { strcat(temp, count++ ? "-PSH" : "PSH"); }
    if (flags & TCP_FLAG_URG) { strcat(temp, count++ ? "-URG" : "URG"); }

    if (count == 0) {
        snprintf(out, out_len, "[NONE]");
    } else {
        snprintf(out, out_len, "[%s]", temp);
    }
}

int parse_tcp(const u_char *buffer, int size, ParsedPacket *pkt) {
    if (size < (int)sizeof(TCPHeader)) return -1;

    const TCPHeader *tcp = (const TCPHeader *)buffer;

    pkt->src_port = ntohs(tcp->src_port);
    pkt->dest_port = ntohs(tcp->dest_port);
    pkt->tcp_seq = ntohl(tcp->seq_num);
    pkt->tcp_ack = ntohl(tcp->ack_num);
    pkt->tcp_flags = tcp->flags;
    pkt->tcp_window = ntohs(tcp->window_size);

    /* Bitwise extraction of TCP data offset (header length in 32-bit words) */
    pkt->tcp_header_len = (uint8_t)(((tcp->data_offset_res >> 4) & 0x0F) * 4);
    if (pkt->tcp_header_len < sizeof(TCPHeader) || pkt->tcp_header_len > size) {
        pkt->tcp_header_len = sizeof(TCPHeader);
    }

    format_tcp_flags(tcp->flags, pkt->tcp_flags_str, sizeof(pkt->tcp_flags_str));

    pkt->transport = PROTO_TCP;

    /* Detect common applications */
    if (pkt->src_port == 80 || pkt->dest_port == 80 ||
        pkt->src_port == 8080 || pkt->dest_port == 8080) {
        pkt->app_proto = APP_HTTP;
        pkt->app_str = "HTTP";
    } else if (pkt->src_port == 443 || pkt->dest_port == 443) {
        pkt->app_proto = APP_HTTPS;
        pkt->app_str = "HTTPS";
    } else if (pkt->src_port == 53 || pkt->dest_port == 53) {
        pkt->app_proto = APP_DNS;
        pkt->app_str = "DNS";
    }

    return pkt->tcp_header_len;
}

int parse_udp(const u_char *buffer, int size, ParsedPacket *pkt) {
    if (size < (int)sizeof(UDPHeader)) return -1;

    const UDPHeader *udp = (const UDPHeader *)buffer;

    pkt->src_port = ntohs(udp->src_port);
    pkt->dest_port = ntohs(udp->dest_port);
    pkt->udp_length = ntohs(udp->length);
    pkt->transport = PROTO_UDP;

    if (pkt->src_port == 53 || pkt->dest_port == 53) {
        pkt->app_proto = APP_DNS;
        pkt->app_str = "DNS";
    } else if (pkt->src_port == 67 || pkt->dest_port == 67 ||
               pkt->src_port == 68 || pkt->dest_port == 68) {
        pkt->app_proto = APP_OTHER;
        pkt->app_str = "DHCP";
    } else if (pkt->src_port == 123 || pkt->dest_port == 123) {
        pkt->app_proto = APP_OTHER;
        pkt->app_str = "NTP";
    }

    return sizeof(UDPHeader);
}

int parse_icmp(const u_char *buffer, int size, ParsedPacket *pkt) {
    if (size < (int)sizeof(ICMPHeader)) return -1;

    const ICMPHeader *icmp = (const ICMPHeader *)buffer;

    pkt->icmp_type = icmp->type;
    pkt->icmp_code = icmp->code;
    pkt->transport = PROTO_ICMP;

    switch (icmp->type) {
        case 0:  pkt->icmp_type_str = "Echo Reply"; break;
        case 3:  pkt->icmp_type_str = "Dest Unreachable"; break;
        case 5:  pkt->icmp_type_str = "Redirect"; break;
        case 8:  pkt->icmp_type_str = "Echo Request"; break;
        case 11: pkt->icmp_type_str = "Time Exceeded"; break;
        default: pkt->icmp_type_str = "Control Message"; break;
    }

    return sizeof(ICMPHeader);
}

int parse_packet(const struct pcap_pkthdr *header, const u_char *buffer, ParsedPacket *pkt) {
    if (header == NULL || buffer == NULL || pkt == NULL) return -1;

    memset(pkt, 0, sizeof(ParsedPacket));
    pkt->timestamp = header->ts;
    pkt->caplen = header->caplen;
    pkt->wirelen = header->len;

    int remaining = header->caplen;
    const u_char *ptr = buffer;

    /* 1. Parse Ethernet Frame */
    int eth_len = parse_ethernet(ptr, remaining, pkt);
    if (eth_len < 0) return -1;

    ptr += eth_len;
    remaining -= eth_len;

    /* 2. Parse IPv4 Packet if present */
    if (pkt->ethertype == ETHERTYPE_IP) {
        int ip_len = parse_ip(ptr, remaining, pkt);
        if (ip_len < 0) return -1;

        ptr += ip_len;
        remaining -= ip_len;

        /* 3. Parse Transport Layer */
        int trans_len = 0;
        if (pkt->ip_protocol == IPPROTO_TCP_VAL) {
            trans_len = parse_tcp(ptr, remaining, pkt);
        } else if (pkt->ip_protocol == IPPROTO_UDP_VAL) {
            trans_len = parse_udp(ptr, remaining, pkt);
        } else if (pkt->ip_protocol == IPPROTO_ICMP_VAL) {
            trans_len = parse_icmp(ptr, remaining, pkt);
        } else {
            pkt->transport = PROTO_OTHER;
        }

        if (trans_len > 0) {
            ptr += trans_len;
            remaining -= trans_len;
        }

        /* 4. Store remaining payload reference */
        if (remaining > 0) {
            pkt->payload = ptr;
            pkt->payload_len = (uint32_t)remaining;
        }
    } else {
        pkt->transport = PROTO_OTHER;
    }

    return 0;
}
