#include "ip_parser.h"

int parse_ip_packet(packet_data *pkt){

    if (pkt == NULL || pkt->ip_data == NULL || pkt->info_len == 0){
        return -1;

    }
    pkt->final_data = NULL;

    // determining the IP version (ethertype or the first byte if LINTYPE_RAW)
    uint8_t version = 0;
    if (pkt->ether_type == 0x0800){
        
        version = 4;
    } else if (pkt->ether_type == 0x86DD){
        
        version = 6;
    } else if (pkt->ether_type == 0){
        // if LINKTYPE_RAW version is in the first 4 bits of the header
        version = (pkt->ip_data[0] >> 4) & 0x0F;
    } else {
        
        printf("Protokół różny od IP");
        return 0;
    }

    if (version != 4 && version != 6){
        
        printf("Protokół różny od IP");
        return 0;
    }

    // initializing a new strucutre using zeros
    ip_info *info = (ip_info *)calloc(1, sizeof(ip_info));
    if (info == NULL) {
        
        perror("Nie udało się przydzielić pamięci dla informacji o IP!");
        return -1;
    }

    info->ip_version = version;
    info->total_pack_len = pkt->original_len;

    uint32_t transport_offset = 0;
    uint32_t real_ip_len = 0;

    if (version == 4) {
        // shorstest ip v4header has 20 bytes
        if (pkt->info_len < 20 || ((pkt->ip_data[0] >> 4) & 0x0F) != 4){
            
            free(info);
            perror("Niepoprawny nagłówek IPv4!");
            return -1;
        }

        uint8_t ihl = (pkt->ip_data[0] & 0x0F) * 4;
        if (ihl < 20 || pkt->info_len < ihl){ 
            
            free(info);
            return -1;
        }

        // if etherent added padding on the end of the frame it gets felteted here
        uint16_t ip_total_len = ((uint16_t)pkt->ip_data[2] << 8) | pkt->ip_data[3];
        if (ip_total_len < ihl){
            
            free(info);
            return -1;
        }
        // if shorter than declared its all right, if longer its not (segfault)
        real_ip_len = (ip_total_len <= pkt->info_len) ? ip_total_len : pkt->info_len;

        // ip packet fragmentation flags
        uint16_t fragmenmt_flags = ((uint16_t)pkt->ip_data[6] << 8) | pkt->ip_data[7];
        bool more_fragments = (fragmenmt_flags & 0x2000) != 0;
        uint16_t fragment_offset = (fragmenmt_flags & 0x1FFF) * 8;

        info->is_fragmented = more_fragments || (fragment_offset > 0);
        info->frag_offset = fragment_offset;

        //protocol field in header
        info->protocol_type = pkt->ip_data[9];

        if (inet_ntop(AF_INET, &pkt->ip_data[12], info->src_ip, sizeof(info->src_ip)) == NULL || inet_ntop(AF_INET, &pkt->ip_data[16], info->dest_ip, sizeof(info->dest_ip)) == NULL){
            
            free(info);
            perror("Błąd podczas konwersji adresu IP na tekst!");
            return -1;
        }

        transport_offset = ihl;
    } 

    else{
        // IPV6 header 40 bytes constatn
        if (pkt->info_len < 40 || ((pkt->ip_data[0] >> 4) & 0x0F) != 6) {
            
            free(info);
            perror("Niepoprawny nagłówek IPv6!");
            return -1;
        }

        uint16_t ipv6_payload_len = ((uint16_t)pkt->ip_data[4] << 8) | pkt->ip_data[5];
        uint32_t total_v6 = (uint32_t)40 + ipv6_payload_len;
        // same as in ipv4, avoiding segfault
        real_ip_len = (total_v6 <= pkt->info_len) ? total_v6 : pkt->info_len;

        // tcp or udp or antyhing really
        info->protocol_type = pkt->ip_data[6]; 
        info->is_fragmented = false;
        info->frag_offset = 0;

        if (inet_ntop(AF_INET6, &pkt->ip_data[8], info->src_ip, sizeof(info->src_ip)) == NULL || inet_ntop(AF_INET6, &pkt->ip_data[24], info->dest_ip, sizeof(info->dest_ip)) == NULL){
            
            free(info);
            perror("Błąd podczas konwersji adresu IP na tekst!");
            return -1;
        }

        transport_offset = 40;
    }

    // parsing tcp or udp stuff only if first fragment 
    if (info->frag_offset == 0 && real_ip_len > transport_offset){

        const uint8_t *transport_layer_data = pkt->ip_data + transport_offset;
        uint32_t transport_layer_len = real_ip_len - transport_offset;

        // TCP parsing
        if (info->protocol_type == 6){ 
            if (transport_layer_len < 20){
                
                free(info);
                perror("Błąd długości protokołu TCP!");
                return -1;
            }

            info->src_port = ((uint16_t)transport_layer_data[0] << 8) | transport_layer_data[1];
            info->dest_port = ((uint16_t)transport_layer_data[2] << 8) | transport_layer_data[3];

            info->seq_num = ((uint32_t)transport_layer_data[4] << 24) | ((uint32_t)transport_layer_data[5] << 16) | ((uint32_t)transport_layer_data[6] << 8)  | (uint32_t)transport_layer_data[7];

            info->ack_num = ((uint32_t)transport_layer_data[8] << 24) | ((uint32_t)transport_layer_data[9] << 16) | ((uint32_t)transport_layer_data[10] << 8) | (uint32_t)transport_layer_data[11];

            uint8_t tcp_head_len = ((transport_layer_data[12] >> 4) & 0x0F) * 4;
            if (tcp_head_len < 20 || transport_layer_len < tcp_head_len){

                free(info);
                perror("Niepoprawna długość nagłówka TCP!");
                return -1;
            }

            info->tcp_flags = transport_layer_data[13];
            info->window_size = ((uint16_t)transport_layer_data[14] << 8) | transport_layer_data[15];
            info->tcp_payload_len = transport_layer_len - tcp_head_len;

        }
        // UDP parsing
        else if (info->protocol_type == 17){
            if (transport_layer_len < 8){
                free(info);
                perror("Pakiet UDP jest zbyt krótki!");
                return -1;
            }

            info->src_port = ((uint16_t)transport_layer_data[0] << 8) | transport_layer_data[1];
            info->dest_port = ((uint16_t)transport_layer_data[2] << 8) | transport_layer_data[3];

            uint16_t udp_total_len = ((uint16_t)transport_layer_data[4] << 8) | transport_layer_data[5];

            uint32_t real_udp_len = (udp_total_len <= transport_layer_len) ? udp_total_len : transport_layer_len;
            info->tcp_payload_len = real_udp_len - 8;
        }
    }

    pkt->final_data = info;
    return 0;
}
