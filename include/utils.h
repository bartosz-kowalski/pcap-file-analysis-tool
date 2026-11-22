#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <arpa/inet.h>
#include "packet_parser.h"
#include "header_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

typedef struct{
    char ip[INET6_ADDRSTRLEN]; 
    uint64_t bytes; 
    uint32_t packs;
}host_stat_t;

typedef struct{
    uint16_t port; 
    uint8_t protocol; 
    uint64_t bytes; 
    uint32_t packs;
}port_stat_t;

typedef struct {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    double t_first;
    double t_last;
    uint64_t bytes;
    uint32_t packs;

    bool has_syn;
    bool has_syn_ack;
    bool has_ack;
    bool has_fin;
    bool has_rst;
    uint32_t max_seq;
    uint32_t retransmissions;
    uint32_t out_of_order;
    uint32_t last_seq;
    uint32_t payload_packets;

    uint64_t bytes_up;
    uint64_t bytes_down;
} flow_t;

typedef struct {
    size_t host_count;
    size_t port_count;
    size_t flow_count;
    uint32_t established;
    uint32_t closed_fin;
    uint32_t aborted_rst;
    uint32_t failed_syn;
    uint32_t retransmissions;
    uint32_t out_of_order;
    uint32_t frag_packets;
    uint32_t dns_packets;
    uint32_t syn_without_synack;
    uint32_t zero_window_packets;
    double avg_iat;
    double avg_packet_size;
    uint32_t min_packet_size;
    uint32_t max_packet_size;
    uint32_t median_packet_size;
    uint32_t p95_packet_size;
} traffic_summary_t;

double get_packet_time(const packet_data *, bool);

void analyze_traffic(const packet_data *packets, const header_data *hdr,
                     host_stat_t **hosts, size_t *host_count,
                     port_stat_t **ports, size_t *port_count,
                     flow_t **flows, size_t *flow_count,
                     traffic_summary_t *summary);

#endif