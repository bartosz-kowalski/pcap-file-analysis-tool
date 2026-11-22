#ifndef PACKET_PARSER
#define PACKET_PARSER

#include "header_parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LEN (14)

typedef struct ip_info{
    char src_ip[INET6_ADDRSTRLEN]; // inet_ntop(AF_INET, &ip_data[12], src_ip, sizeof(src_ip));
    char dest_ip[INET6_ADDRSTRLEN]; // inet_ntop(AF_INET6, &ip_data[8], buf, INET6_ADDRSTRLEN) for ipv6
    uint8_t ip_version;

    uint16_t src_port;
    uint16_t dest_port;
    uint8_t protocol_type; // 6 for TCP 17 for UDP higher for other

    uint32_t total_pack_len;   
    uint32_t tcp_payload_len;

    // TCP stuff
    uint8_t tcp_flags; // FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
    uint32_t seq_num; // bytes 4 to 7
    uint32_t ack_num; // bytes 8 to 11
    uint16_t window_size; // bytes 14 to 15

    // ipv4 fragmentation (no headers in fragments)
    bool is_fragmented;
    uint16_t frag_offset;

}ip_info;

typedef struct packet_data{
    uint32_t timestamp_sec;
    uint32_t timestamp_2;
    uint32_t captured_len;
    uint32_t original_len;
    uint32_t info_len;
    uint8_t *raw_data;
    uint8_t *ip_data;
    uint16_t ether_type;
    ip_info* final_data;
}packet_data;

int strip_ethernet_header(packet_data *, const header_data*);

int strip_80211_header(packet_data*, const header_data*);

int parse_packets(FILE*, packet_data*, header_data*);

#endif
