#include "utils.h"

double get_packet_time(const packet_data *pkt, bool sec_micro){
    double t = (double)pkt->timestamp_sec;
    t += sec_micro ? ((double)pkt->timestamp_2 / 1e6) : ((double)pkt->timestamp_2 / 1e9);
    return t;
}

static double get_time(const packet_data *pkt, bool sec_micro) {
    return (double)pkt->timestamp_sec + (sec_micro ? pkt->timestamp_2 / 1e6 : pkt->timestamp_2 / 1e9);
}

static int cmp_hosts(const void *a, const void *b) {
    uint64_t ba = ((host_stat_t*)a)->bytes;
    uint64_t bb = ((host_stat_t*)b)->bytes;
    return (bb > ba) - (bb < ba);
}

static int cmp_ports(const void *a, const void *b) {
    uint64_t ba = ((port_stat_t*)a)->bytes;
    uint64_t bb = ((port_stat_t*)b)->bytes;
    return (bb > ba) - (bb < ba);
}

static int cmp_packet_sizes(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

void analyze_traffic(const packet_data *packets, const header_data *hdr,
                     host_stat_t **hosts, size_t *host_count,
                     port_stat_t **ports, size_t *port_count,
                     flow_t **flows, size_t *flow_count,
                     traffic_summary_t *summary) {
    *hosts = calloc(hdr->packet_no * 2, sizeof(host_stat_t));
    *ports = calloc(hdr->packet_no * 2, sizeof(port_stat_t));
    *flows = calloc(hdr->packet_no, sizeof(flow_t));
    host_stat_t *host_list = *hosts;
    port_stat_t *port_list = *ports;
    flow_t *flow_list = *flows;
    uint64_t *up_bytes = calloc(hdr->packet_no, sizeof(uint64_t));
    uint64_t *dn_bytes = calloc(hdr->packet_no, sizeof(uint64_t));
    uint32_t *packet_sizes = calloc(hdr->packet_no, sizeof(uint32_t));

    size_t host_cnt = 0, port_cnt = 0, flow_cnt = 0;
    uint32_t frag_packets = 0;
    uint32_t dns_packets = 0;
    uint32_t syn_without_synack = 0;
    uint32_t zero_window_packets = 0;
    double total_iat = 0.0;
    uint64_t total_packet_bytes = 0;
    uint32_t min_packet_size = hdr->packet_no > 0 ? packets[0].original_len : 0;
    uint32_t max_packet_size = 0;
    memset(summary, 0, sizeof(*summary));

    for (uint32_t i = 0; i < hdr->packet_no; i++) {
        const ip_info *info = packets[i].final_data;
        if (!info) continue;

        double t = get_time(&packets[i], hdr->sec_micro);
        uint32_t len = packets[i].original_len;
        packet_sizes[i] = len;
        total_packet_bytes += len;
        if (len < min_packet_size) min_packet_size = len;
        if (len > max_packet_size) max_packet_size = len;

        if (i > 0) {
            double prev_t = get_time(&packets[i - 1], hdr->sec_micro);
            if (t >= prev_t) total_iat += (t - prev_t);
        }

        if (info->is_fragmented || info->frag_offset > 0) {
            frag_packets++;
        }
        if (info->src_port == 53 || info->dest_port == 53) {
            dns_packets++;
        }
        if (info->protocol_type == 6 && info->window_size == 0) {
            zero_window_packets++;
        }

        const char *ips[2] = { info->src_ip, info->dest_ip };
        for (int k = 0; k < 2; k++) {
            int found = -1;
            for (size_t j = 0; j < host_cnt; j++) {
                if (strcmp(host_list[j].ip, ips[k]) == 0) { found = (int)j; break; }
            }
            if (found == -1) {
                found = (int)host_cnt++;
                strcpy(host_list[found].ip, ips[k]);
            }
            host_list[found].bytes += len;
            host_list[found].packs++;
        }

        uint16_t prts[2] = { info->src_port, info->dest_port };
        for (int k = 0; k < 2; k++) {
            if (prts[k] == 0) continue;
            int found = -1;
            for (size_t j = 0; j < port_cnt; j++) {
                if (port_list[j].port == prts[k] && port_list[j].protocol == info->protocol_type) {
                    found = (int)j; break;
                }
            }
            if (found == -1) {
                found = (int)port_cnt++;
                port_list[found].port = prts[k];
                port_list[found].protocol = info->protocol_type;
            }
            port_list[found].bytes += len;
            port_list[found].packs++;
        }

        int f_idx = -1;
        bool is_upload = true;

        for (size_t j = 0; j < flow_cnt; j++) {
            if (flow_list[j].protocol != info->protocol_type) continue;

            if (strcmp(flow_list[j].src_ip, info->src_ip) == 0 && strcmp(flow_list[j].dst_ip, info->dest_ip) == 0 &&
                flow_list[j].src_port == info->src_port && flow_list[j].dst_port == info->dest_port) {
                f_idx = (int)j;
                is_upload = true;
                break;
            }
            if (strcmp(flow_list[j].src_ip, info->dest_ip) == 0 && strcmp(flow_list[j].dst_ip, info->src_ip) == 0 &&
                flow_list[j].src_port == info->dest_port && flow_list[j].dst_port == info->src_port) {
                f_idx = (int)j;
                is_upload = false;
                break;
            }
        }

        if (f_idx == -1) {
            f_idx = (int)flow_cnt++;
            strcpy(flow_list[f_idx].src_ip, info->src_ip);
            strcpy(flow_list[f_idx].dst_ip, info->dest_ip);
            flow_list[f_idx].src_port = info->src_port;
            flow_list[f_idx].dst_port = info->dest_port;
            flow_list[f_idx].protocol = info->protocol_type;
            flow_list[f_idx].t_first = t;
            is_upload = true;
        }

        flow_t *f = &flow_list[f_idx];
        f->t_last = t;
        f->bytes += len;
        f->packs++;

        if (is_upload) up_bytes[f_idx] += len;
        else dn_bytes[f_idx] += len;

        if (info->protocol_type == 6) {
            uint8_t fl = info->tcp_flags;
            if ((fl & TCP_SYN) && !(fl & TCP_ACK)) {
                f->has_syn = true;
                syn_without_synack++;
            }
            if ((fl & TCP_SYN) && (fl & TCP_ACK))  f->has_syn_ack = true;
            if (!(fl & TCP_SYN) && (fl & TCP_ACK)) f->has_ack = true;
            if (fl & TCP_FIN) f->has_fin = true;
            if (fl & TCP_RST) f->has_rst = true;

            if (is_upload && info->tcp_payload_len > 0) {
                f->payload_packets++;
                if (f->payload_packets > 1 && info->seq_num == f->last_seq) {
                    f->retransmissions++;
                }
                else if (f->max_seq > 0 && info->seq_num < f->max_seq) {
                    f->out_of_order++;
                }
                if (info->seq_num > f->max_seq) {
                    f->max_seq = info->seq_num;
                }
                f->last_seq = info->seq_num;
            }
        }
    }

    qsort(host_list, host_cnt, sizeof(host_stat_t), cmp_hosts);
    qsort(port_list, port_cnt, sizeof(port_stat_t), cmp_ports);

    printf("\n--- 5 NAJAKTYWNIEJSZYCH HOSTÓW ---\n");
    printf("%-4s %-46s %-14s %s\n", "Lp.", "Adres IP", "Przesłane bajty", "Pakiety");
    for (size_t i = 0; i < (host_cnt < 5 ? host_cnt : 5); i++) {
        printf("%-4zu %-46s %-14lu  %u\n",
               i + 1,
               host_list[i].ip,
               host_list[i].bytes,
               host_list[i].packs);
    }

    printf("\n--- 5 NAJAKTYWNIEJSZYCH PORTÓW ---\n");
    for (size_t i = 0; i < (port_cnt < 5 ? port_cnt : 5); i++) {
        printf("%zu. Port %u (protokół %u) -> %lu B (%u pakietów)\n", i + 1, port_list[i].port, port_list[i].protocol, port_list[i].bytes, port_list[i].packs);
    }

    uint32_t established = 0, closed_fin = 0, aborted_rst = 0, failed_syn = 0;
    uint32_t total_retrans = 0, total_out_of_order = 0;

    printf("\n--- SESJE (Liczba: %zu) ---\n", flow_cnt);
    for (size_t i = 0; i < flow_cnt; i++) {
        flow_t *f = &flow_list[i];
        double dur = f->t_last - f->t_first;
        double ratio = (dn_bytes[i] > 0) ? (double)up_bytes[i] / dn_bytes[i] : (double)up_bytes[i];

        if (f->protocol == 6) {
            if (f->has_syn && f->has_syn_ack && f->has_ack) established++;
            if (f->has_fin) closed_fin++;
            if (f->has_rst) aborted_rst++;
            if (f->has_syn && !f->has_syn_ack) failed_syn++;
            total_retrans += f->retransmissions;
            total_out_of_order += f->out_of_order;
        }

        if (i < 10) {
            printf("Sesja %zu: %s:%u <-> %s:%u | Czas: %.3f s | Wysyłanie/Odbieranie: %lu/%lu B (Współczynnik: %.2f)\n",
                   i + 1, f->src_ip, f->src_port, f->dst_ip, f->dst_port, dur, up_bytes[i], dn_bytes[i], ratio);
            printf("  Średnia przepustowość sesji: %.2f KB/s | Pakiety: %u\n",
                   dur > 0.0 ? (double)f->bytes / 1024.0 / dur : (double)f->bytes / 1024.0,
                   f->packs);
        }
    }

    double avg_iat = (hdr->packet_no > 1) ? total_iat / (hdr->packet_no - 1) : 0.0;
    qsort(packet_sizes, hdr->packet_no, sizeof(uint32_t), cmp_packet_sizes);
    uint32_t median = hdr->packet_no > 0
        ? packet_sizes[hdr->packet_no / 2]
        : 0;
    uint32_t p95 = hdr->packet_no > 0
        ? packet_sizes[(hdr->packet_no * 95 + 99) / 100 - 1]
        : 0;
    double avg_packet_size = hdr->packet_no > 0
        ? (double)total_packet_bytes / hdr->packet_no
        : 0.0;

    printf("\n--- PODSUMOWANIE TCP I ANOMALII ---\n");
    printf("Poprawne uzgadnianie połączenia (3-way handshake): %u\n", established);
    printf("Zakończone FIN: %u | Przerwane RST: %u\n", closed_fin, aborted_rst);
    printf("Nieudane SYN (bez odpowiedzi): %u\n", failed_syn);
    printf("Potencjalne skany/próby SYN: %u\n", syn_without_synack >= 5 ? syn_without_synack : 0);
    printf("Średni czas między przybyciem pakietów (IAT): %.6f s\n", avg_iat);
    printf("Retransmisje TCP: %u\n", total_retrans);
    printf("Pakiety TCP poza kolejnością: %u\n", total_out_of_order);
    printf("Pakiety pofragmentowane (IPv4): %u\n", frag_packets);
    printf("Pakiety DNS: %u\n", dns_packets);
    printf("Pakiety z zerowym oknem TCP: %u\n", zero_window_packets);

    printf("\n--- STATYSTYKI ROZMIARÓW PAKIETÓW ---\n");
    printf("Średni: %.2f B | Mediana: %u B | 95. percentyl: %u B | Zakres: %u-%u B\n",
           avg_packet_size, median, p95, min_packet_size, max_packet_size);

    summary->host_count = host_cnt;
    summary->port_count = port_cnt;
    summary->flow_count = flow_cnt;
    summary->established = established;
    summary->closed_fin = closed_fin;
    summary->aborted_rst = aborted_rst;
    summary->failed_syn = failed_syn;
    summary->retransmissions = total_retrans;
    summary->out_of_order = total_out_of_order;
    summary->frag_packets = frag_packets;
    summary->dns_packets = dns_packets;
    summary->syn_without_synack = syn_without_synack;
    summary->zero_window_packets = zero_window_packets;
    summary->avg_iat = avg_iat;
    summary->avg_packet_size = avg_packet_size;
    summary->min_packet_size = min_packet_size;
    summary->max_packet_size = max_packet_size;
    summary->median_packet_size = median;
    summary->p95_packet_size = p95;
    *host_count = host_cnt;
    *port_count = port_cnt;
    *flow_count = flow_cnt;

    free(up_bytes);
    free(dn_bytes);
    free(packet_sizes);
} 
