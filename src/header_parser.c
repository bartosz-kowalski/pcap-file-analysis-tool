#include "header_parser.h"

int is_header_valid(FILE *pcap_file, header_data *data){

    uint32_t file_data;
    uint32_t magic_no_data;
    uint16_t link_data;
    uint32_t network_field;
    size_t elements_read;

    // Reading the magic number
    elements_read= fread(&magic_no_data, 4, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    if(magic_no_data == 0xA1B2C3D4){
        data->sec_micro = true;
        data->endianness = false;
    }
    else if(magic_no_data == 0xA1B23C4D){
        data->sec_micro = false;
        data->endianness = false;
    }
    else if(magic_no_data == __builtin_bswap32(0xA1B2C3D4)){
        data->sec_micro = true;
        data->endianness = true;
    }
    else if(magic_no_data == __builtin_bswap32(0xA1B23C4D)){
        data->sec_micro = false;
        data->endianness = true;
    }
    else{
        perror("Niepoprawny nagłówek! Niepoprawny numer magiczny! \n");
        return -1;
    }

    // Checking both the minor and major version
    for(int i = 0; i < 2; i++){
        elements_read = fread(&link_data, 2, 1, pcap_file);
        CHECK_READ_HEADER(elements_read, 1, pcap_file);

        if(data->endianness){
            // changing endianness if needed
            link_data = __builtin_bswap16(link_data);
        }

        if(link_data == 2 && i == 0){
            continue;
        }
        else if(link_data == 4 && i == 1){
            continue;
        }
        else{
            perror("Niepoprawny numer wersji! \n");
            return -1;
        }
    }

    // Skipping the reserved bits
    for(int i = 0; i < 2; i++){
        elements_read = fread(&file_data, 4, 1, pcap_file);
        CHECK_READ_HEADER(elements_read, 1, pcap_file);
        continue;
    }

    // Reading the SnapLen
    elements_read = fread(&file_data, 4, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    if(data->endianness){
        // changing endianness if needed
        file_data = __builtin_bswap32(file_data);
    }
    data->SnapLen = file_data;

    // reading all 4 bytes of linktype and fcs
    elements_read = fread(&network_field, 4, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);

    if (data->endianness) {
        // changing endianness if needed
        network_field = __builtin_bswap32(network_field);
    }

    data->LinkType = network_field & 0xFFFF;

    bool F = (network_field & (1U << 28)) != 0;
    if (F) {
        data->FCS = ((network_field >> 29) & 0x07) * 2;
    } else {
        data->FCS = 0;
    }

    printf("Prawidłowo przetworzono nagłówek pliku! \n");

    return 0;
}

int check_packet_no(FILE *pcap_file, header_data *data){

    uint32_t file_data; // timestamps and original packet length
    uint32_t captured_len;
    uint32_t no_packs = 0;
    size_t elements_read;

    while(1){
        // reding the packet timestamp (eof is valid)
        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read == 0 && feof(pcap_file)) {
            printf("Skończono odczyt pakietów (EOF)!\n");
            break; 
        }
        if (elements_read != 1) {
            perror("Błąd podczas odczytu znacznika czasu pakietu! \n");
            return -1;
        }

        // readin the rest of the packet header (eof indicates an error)
        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read != 1) {
            perror("Nieoczekiwany koniec pliku (EOF)! \n");
            return -1;
        }

        elements_read = fread(&captured_len, 4, 1, pcap_file);
        if(data->endianness == true){
            // changing endianness if needed
            captured_len = __builtin_bswap32(captured_len);
        }
        if (elements_read != 1) {
            perror("Nieoczekiwany koniec pliku podczas odczytu przechwyconej długości! \n");
            return -1;
        }

        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read != 1){
            perror("Uszkodzony nagłówek pakietu (brak pierwotnej długości pakietu)! \n");
            return -1;
        }

        // Skipping packet data and checking EOF
        if (captured_len > 0) {
            if (fseek(pcap_file, captured_len - 1, SEEK_CUR) != 0){
                perror("Nie udało się pominąć danych pakietu! \n");
                return -1;
            }
            uint8_t buf;
            if (fread(&buf, 1, 1, pcap_file) != 1){
                perror("Nieoczekiwany koniec pliku w danych pakietu! \n");
                return -1;
            }
        }
        
        no_packs += 1;
    }
    
    data->packet_no = no_packs;

    // returning to the start of the file
    if (fseek(pcap_file, 0L, SEEK_SET) != 0){
        perror("Nie udało się wrócić na początek pliku! \n");
    }

    // skipping the header
    fseek(pcap_file, HEADER_LENGTH, SEEK_CUR);

    return 0;
}
