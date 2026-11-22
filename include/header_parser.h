#ifndef HEADER_PARSER
#define HEADER_PARSER

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define HEADER_LENGTH (24)

#define LINKTYPE_ETHERNET 1
#define LINKTYPE_RAW 101
#define LINKTYPE_IEEE802_11 105
#define LINKTYPE_LINUX_SSL 113

// Macro for checking if header data was read correctly
#define CHECK_READ_HEADER(bytes_read, bytes_expected, file)\
    if ((bytes_read) < (size_t)(bytes_expected)) { \
        if (feof(file)) { \
            printf("Osiągnięto koniec pliku (EOF)! \n"); \
        } else if (ferror(file)) { \
            perror("Wystąpił błąd podczas odczytu danych"); \
        } \
        return -1; \
    } \

typedef struct {
    bool sec_micro; // 0 is nanoseconds 1 is microseconds
    uint32_t SnapLen;
    uint8_t FCS;
    uint16_t LinkType;
    uint32_t packet_no;
    bool endianness; // 0 is Little 1 is Big
}header_data;

int is_header_valid(FILE*, header_data*);

int check_packet_no(FILE*, header_data*);

#endif
