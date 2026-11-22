#ifndef REPORT
#define REPORT

#include "utils.h"

#define AUTHOR   ("TPiW - Trzech Pancernych i Wilk")
#define CREATOR  ("PCAP file analysis tool")
#define SUBJECT  ("Analiza ruchu sieciowego z pliku PCAP")
#define TITLE    ("Raport analizy PCAP")

int generate_report(const char *output_path,
                     const packet_data *packets, const header_data *hdr,
                     const host_stat_t *hosts, const size_t host_count,
                     const port_stat_t *ports, const size_t port_count,
                     const flow_t *flows, const size_t flow_count,
                     const char *const *images, const size_t image_count,
                     const traffic_summary_t *summary);

#endif