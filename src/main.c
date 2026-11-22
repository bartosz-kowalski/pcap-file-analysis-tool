#include "header_parser.h"
#include "packet_parser.h"
#include "ip_parser.h"
#include "plotting.h"
#include "utils.h"
#include "report.h"

#include <string.h>
#include <stdlib.h>
#include <strings.h>

#define NUM_BINS (200)

static char *make_report_filename(const char *requested, const char *pcap_path) {
    const char *source = requested != NULL ? requested : pcap_path;
    size_t length = strlen(source);
    bool has_pdf_extension = requested != NULL &&
        length >= 4 && strcasecmp(source + length - 4, ".pdf") == 0;

    if (requested == NULL && length >= 5 &&
        strcasecmp(source + length - 5, ".pcap") == 0) {
        length -= 5;
    }

    size_t extension_length = has_pdf_extension ? 0 : 4;
    char *filename = malloc(length + extension_length + 1);
    if (filename == NULL) return NULL;

    memcpy(filename, source, length);
    if (extension_length > 0) {
        memcpy(filename + length, ".pdf", 5);
    } else {
        filename[length] = '\0';
    }
    return filename;
}

int main(int argc, char **argv){

    /*
    The first argument must be the filename (incl. the extension)
    The second one may be the name of the output file
    Names MUST NOT contain spaces or any special characters
    */

    char *pcap_filename = NULL;
    char *output_filename = NULL;

    if(argc < 2){
        perror("Należy podać jako argument nazwę pliku .PCAP!\n");
        return -1;
    }
    else if(argc > 3){
        perror("Podano zbyt wiele argumentów! \n");
        return -1;
    }
    else{
        // We have to determine the length of the filename (+1 because of '\0' character)
        // Then allocate memory for a copy and copy it
        size_t pcap_filename_len = strlen(argv[1]) + 1;
        pcap_filename = (char*)malloc(pcap_filename_len);
        memcpy(pcap_filename, argv[1], pcap_filename_len);

    }

    output_filename = make_report_filename(argc == 3 ? argv[2] : NULL, pcap_filename);
    if (output_filename == NULL) {
        fprintf(stderr, "Nie udało się utworzyć nazwy pliku raportu.\n");
        free(pcap_filename);
        return -1;
    }

    FILE *pcap_file = NULL;
    pcap_file = fopen(pcap_filename, "rb");
    if(pcap_file == NULL){
        perror("Nie można otworzyć pliku! \n");
        return -1;
    }

    header_data pcap_header_data;
    int valid = is_header_valid(pcap_file, &pcap_header_data);
    if(valid != 0){
        printf("BŁĄD NAGŁÓWKA! \n");
        return -1;
    }
    printf("Numer magiczny: %d, snaplen: %d, fcs: %d, typ linku: %d \n", pcap_header_data.sec_micro, pcap_header_data.SnapLen, pcap_header_data.FCS, pcap_header_data.LinkType);

    if (check_packet_no(pcap_file, &pcap_header_data) != 0){
        printf("BŁĄD W LICZENIU PAKIETÓW! \n");
        return -1;
    } 
    printf("Liczba pakietów: %d. \n", pcap_header_data.packet_no);

    packet_data *pcap_packets = (packet_data*)malloc(pcap_header_data.packet_no * sizeof(packet_data));
    for(uint32_t i = 0; i < pcap_header_data.packet_no; i++){
        pcap_packets[i].ip_data  = NULL;
        pcap_packets[i].raw_data = NULL;
        pcap_packets[i].final_data = NULL;
    }

    valid = parse_packets(pcap_file, pcap_packets, &pcap_header_data);
    if(valid != 0){
        printf("BŁĄD W PARSOWANIU PAKIETÓW! \n");
        return -1;
    }

    for (uint32_t i = 0; i < pcap_header_data.packet_no; i++){
        if (parse_ip_packet(&pcap_packets[i]) != 0) {
            printf("BŁĄD W PARSOWANIU PAKIETÓW IP %u\n", i);
            return -1;
        }
    }

    uint32_t tcp_packet_no = 0;
    uint32_t udp_packet_no = 0;
    uint32_t other_packet_no = 0;

    uint32_t fin_tcp_no = 0;
    uint32_t ack_tcp_no = 0;
    uint32_t rst_tcp_no = 0;
    uint32_t syn_tcp_no = 0;
    uint32_t psh_tcp_no = 0;

    uint64_t avg_tcp_sz = 0;
    uint64_t avg_udp_sz = 0;
    uint64_t avg_pack_size = 0;

    // throughput data 
    double t_first = get_packet_time(&pcap_packets[0], pcap_header_data.sec_micro);
    double t_last  = get_packet_time(&pcap_packets[pcap_header_data.packet_no - 1], pcap_header_data.sec_micro);
    double total_duration = t_last - t_first;
    printf("Czas trwania: %.6f s (t_first=%.6f, t_last=%.6f)\n", total_duration, t_first, t_last);
    if (total_duration <= 0.0) total_duration = 1e-6;
    uint32_t num_bins = pcap_header_data.packet_no / 3;
    if (num_bins < 10) num_bins = 10;
    if (num_bins > 100) num_bins = 100;
    double bin_width = total_duration / num_bins;
    double *bin_times = calloc(num_bins, sizeof(double));
    double *throughput = calloc(num_bins, sizeof(double));
    double *tcp_throughput = calloc(num_bins, sizeof(double));
    double *udp_throughput = calloc(num_bins, sizeof(double));
    double *other_throughput = calloc(num_bins, sizeof(double));
    for (uint32_t b = 0; b < num_bins; b++) {
        bin_times[b] = (b + 0.5) * bin_width;
    }

    uint32_t max_pack_size = 0;
    uint32_t min_pack_size = pcap_packets[0].original_len;

    uint32_t bytes1_no = 0;
    uint32_t bytes2_no = 0;
    uint32_t bytes3_no = 0;
    uint32_t bytes4_no = 0;
    uint32_t bytes5_no = 0;
    uint32_t bytes6_no = 0;

    port_stat_t *ports = NULL;
    host_stat_t *hosts = NULL;
    flow_t *flows = NULL;
    size_t host_count = 0, port_count = 0, flow_count = 0;
    traffic_summary_t traffic_summary;
    analyze_traffic(pcap_packets, &pcap_header_data,
                    &hosts, &host_count, &ports, &port_count,
                    &flows, &flow_count, &traffic_summary);

    uint32_t fragmented_no = 0;

    for(uint32_t i = 0; i < pcap_header_data.packet_no; i++){
        uint32_t packet_protocol = 0;
        if (pcap_packets[i].final_data != NULL) {
            packet_protocol = pcap_packets[i].final_data->protocol_type;
        }
        // tcp and udp data stuff
        switch(packet_protocol){
            case 6: // TCP
                tcp_packet_no++;
                switch(pcap_packets[i].final_data->tcp_flags){
                    case 0x01:fin_tcp_no++; break;
                    case 0x02: syn_tcp_no++; break;
                    case 0x04: rst_tcp_no++; break;
                    case 0x08: psh_tcp_no++; break;
                    case 0x10: ack_tcp_no++; break;
                    case 0x11: fin_tcp_no++; ack_tcp_no++; break;
                    case 0x12: syn_tcp_no++; ack_tcp_no++; break;
                    case 0x18: psh_tcp_no++; ack_tcp_no++; break;
                    default: break;}
                avg_tcp_sz += pcap_packets[i].final_data->tcp_payload_len;
                break;
            case 17: // UDP
                udp_packet_no++; 
                avg_udp_sz += pcap_packets[i].final_data->tcp_payload_len;
                break;
            default: other_packet_no++; break;
        } 
        if(pcap_packets[i].original_len > max_pack_size){
            max_pack_size = pcap_packets[i].original_len;;
        }
        if(pcap_packets[i].original_len < min_pack_size){
            min_pack_size = pcap_packets[i].original_len;
        }
        avg_pack_size += pcap_packets[i].original_len;

        // throughput (dynamic windows)
        double rel_time = get_packet_time(&pcap_packets[i], pcap_header_data.sec_micro) - t_first;
        uint32_t bin_idx = (uint32_t)(rel_time / bin_width);
        if (bin_idx >= num_bins) bin_idx = num_bins - 1;
        throughput[bin_idx] += (double)pcap_packets[i].original_len;
        if (packet_protocol == 6) tcp_throughput[bin_idx] += (double)pcap_packets[i].original_len;
        else if (packet_protocol == 17) udp_throughput[bin_idx] += (double)pcap_packets[i].original_len;
        else other_throughput[bin_idx] += (double)pcap_packets[i].original_len;

        // histogram of packet sizes
        if(pcap_packets[i].original_len < (uint32_t)64){
            bytes1_no++;
        }
        else if(pcap_packets[i].original_len >= (uint32_t)64 && pcap_packets[i].original_len < (uint32_t)256){
            bytes2_no++;
        }
        else if(pcap_packets[i].original_len >= (uint32_t)256 && pcap_packets[i].original_len < (uint32_t)512){
            bytes3_no++;
        }
        else if(pcap_packets[i].original_len >= (uint32_t)512 && pcap_packets[i].original_len < (uint32_t)1024){
            bytes4_no++;
        }
        else if(pcap_packets[i].original_len >= (uint32_t)1024 && pcap_packets[i].original_len < (uint32_t)1518){
            bytes5_no++;
        }
        else if(pcap_packets[i].original_len  >= 1518){
            bytes6_no++;
        }

        // counting fragmented packets, maybe an anomaly
        if(pcap_packets[i].final_data != NULL &&
           (pcap_packets[i].final_data->is_fragmented == true ||
            pcap_packets[i].final_data->frag_offset > 0)) fragmented_no++;
    }

    if(tcp_packet_no != 0) avg_tcp_sz /= tcp_packet_no;
    else avg_tcp_sz = 0;
    if(udp_packet_no != 0) avg_udp_sz /= udp_packet_no;
    else avg_udp_sz = 0;
    avg_pack_size /= pcap_header_data.packet_no;

    for (uint32_t b = 0; b < num_bins; b++) {
        throughput[b] = (uint64_t)((double)throughput[b] / bin_width) / 1024.0;
        tcp_throughput[b] = (uint64_t)((double)tcp_throughput[b] / bin_width) / 1024.0;
        udp_throughput[b] = (uint64_t)((double)udp_throughput[b] / bin_width) / 1024.0;
        other_throughput[b] = (uint64_t)((double)other_throughput[b] / bin_width) / 1024.0;
    }

    const char *images[] = {
        "images/tcp_v_udp.png",
        "images/throughput.png",
        "images/protokoly_throughput.png",
        "images/top_hosts.png",
        "images/histogram.png",
    };
    generate_protocol_type_chart(images[0], tcp_packet_no, udp_packet_no, other_packet_no);
    generate_throughput_chart(images[1], bin_times, throughput, num_bins);
    generate_protocol_throughput_chart(images[2], bin_times,
                                       tcp_throughput, udp_throughput,
                                       other_throughput, num_bins);
    if (host_count > 0) {
        generate_top_hosts_chart(images[3], hosts, host_count);
    }
    generate_size_chart(images[4], bytes1_no, bytes2_no, bytes3_no, bytes4_no, bytes5_no, bytes6_no);

    int report_result = generate_report(output_filename,
                                        pcap_packets, &pcap_header_data,
                                        hosts, host_count,
                                        ports, port_count,
                                        flows, flow_count,
                                        images, sizeof(images) / sizeof(images[0]),
                                        &traffic_summary);

    // Clean up
    fclose(pcap_file);

    for(uint32_t i = 0; i < pcap_header_data.packet_no; i++){
        free(pcap_packets[i].raw_data);
        free(pcap_packets[i].final_data);
    }

    free(pcap_packets);
    free(pcap_filename);
    free(output_filename);
    free(bin_times);
    free(throughput);
    free(tcp_throughput);
    free(udp_throughput);
    free(other_throughput);
    free(hosts);
    free(ports);
    free(flows);

    return report_result == 0 ? 0 : -1;
}
