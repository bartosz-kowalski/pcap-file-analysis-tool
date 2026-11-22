#include "packet_parser.h"

int strip_ethernet_header(packet_data *pack, const header_data* head){

    // checking if the frame is adequatly sized
    if (pack->captured_len < (uint32_t)ETHERNET_HEADER_LEN  + head->FCS) {
        return -1; // corrupted frame
    }

    // ether type read
    pack->ether_type = ((uint16_t)pack->raw_data[12] << 8) | pack->raw_data[13];

    // ip header starts at 14th byte
    pack->ip_data = pack->raw_data + ETHERNET_HEADER_LEN;
    pack->info_len = pack->captured_len - ETHERNET_HEADER_LEN - head->FCS;

    return 0;
}

int strip_80211_header(packet_data *pack, const header_data *head){
    pack->ip_data = NULL;
    pack->info_len = 0;
    pack->ether_type = 0;

    // minimum length is 24 bytes + fcs (if available)
    if (pack->captured_len < (uint32_t)(24 + head->FCS)){
        perror("Invaild wifi frame");
        return -1; 
    }

    uint8_t fc0 = pack->raw_data[0];
    uint8_t fc1 = pack->raw_data[1];

    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    // we want only data frames (no 2)
    // management and control frames do not carry ip info
    if (type != 2) return 0; 

    // skip if there is no data
    if (subtype == 4 || subtype == 12) return 0;

    // check if frame is encrypted
    if (fc1 & 0x40) return 0;

    // caclulating the whole 802.11 header length
    uint32_t offset = 24;
    if ((fc1 & 0x03) == 0x03) offset += 6;
    if (subtype & 0x08){
        offset += 2;
        if (fc1 & 0x80) offset += 4;
    }

    const uint32_t LLC_SNAP_LEN = 8;
    if (pack->captured_len < offset + LLC_SNAP_LEN + head->FCS){
        perror("Frame too short for LLC header");
        return -1; 
    }

    const uint8_t *llc = pack->raw_data + offset;

    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03){
        // not IP or SNAP protocol
        return 0; 
    }

    // ehter type from last 2 bytes of snap
    pack->ether_type = ((uint16_t)llc[6] << 8) | llc[7];

    // opinter set to real ip data that we want
    uint32_t total_header_len = offset + LLC_SNAP_LEN;
    pack->ip_data = pack->raw_data + total_header_len;
    pack->info_len = pack->captured_len - total_header_len - head->FCS;

    return 0;
}

int parse_packets(FILE* pcap_file, packet_data *data, header_data* packet_header){

    size_t elements_read;
    uint32_t packet_header_data;
    uint32_t packet_no = packet_header->packet_no;

    for(uint32_t i = 0; i < packet_no; i++){

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].timestamp_sec = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].timestamp_2 = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].captured_len = packet_header_data;
        data[i].raw_data = (uint8_t*)malloc(packet_header_data);

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].original_len = packet_header_data;

        elements_read = fread(data[i].raw_data, data[i].captured_len, 1, pcap_file);
        if (elements_read != 1) return -1;

        if(packet_header->LinkType == LINKTYPE_ETHERNET){
            strip_ethernet_header(&data[i], packet_header);
        }
        else if(packet_header->LinkType == LINKTYPE_RAW){
            data[i].ip_data = data[i].raw_data;
            data[i].info_len = data[i].captured_len;
            data[i].ether_type = 0;
        }
        else if(packet_header->LinkType == LINKTYPE_IEEE802_11){
            strip_80211_header(&data[i], packet_header);
        }
    }

    return 0;
}
