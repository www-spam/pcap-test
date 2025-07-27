// libnet_headers.h

#ifndef LIBNET_HEADERS_H
#define LIBNET_HEADERS_H

#include <stdint.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

struct libnet_ipv4_hdr {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4, ip_v:4;
    #elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4, ip_hl:4;
    #endif
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct libnet_tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4, th_off:4;
    #elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4, th_x2:4;
    #endif
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

#endif
