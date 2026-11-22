#include "plotting.h"

int generate_throughput_chart(const char *output_png, const double *times, const double *kbps, size_t count) {
    if (count == 0) return -1;

    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Nie udało się uruchomić programu gnuplot");
        return -1;
    }

    fprintf(gp, "set terminal pngcairo size 1000,620 enhanced font 'Sans,13'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Przepustowość ruchu sieciowego w czasie'\n");
    fprintf(gp, "set xlabel 'Czas od początku przechwytywania [s]'\n");
    fprintf(gp, "set ylabel 'Przepustowość [KB/s]'\n");
    fprintf(gp, "set grid xtics ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set key top right opaque box\n");
    fprintf(gp, "plot '-' using 1:2 with linespoints lw 2 pt 7 ps 0.7 lc rgb '#1f77b4' title 'Przepustowość'\n");

    for (size_t i = 0; i < count; i++) {
        fprintf(gp, "%.6f %.2f\n", times[i], kbps[i]);
    }
    fprintf(gp, "e\n");

    return (pclose(gp) == 0) ? 0 : -1;
}

int generate_protocol_type_chart(const char *output_png, uint32_t tcp_pkts, uint32_t udp_pkts, uint32_t other_pkts){
    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Nie udało się uruchomić programu gnuplot");
        return -1;
    }

    uint64_t all_packs = tcp_pkts + udp_pkts + other_pkts;
    double tcp_percent = all_packs > 0 ? (double)tcp_pkts / all_packs * 100 : 0;
    double udp_percent = all_packs > 0 ? (double)udp_pkts / all_packs * 100 : 0;
    double other_percent = all_packs > 0 ? (double)other_pkts / all_packs * 100 : 0;

    fprintf(gp, "set terminal pngcairo size 1000,620 enhanced font 'Sans,13'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title \"Analiza ruchu sieciowego\\n{/*0.8 TCP: %.1f%%, UDP: %.1f%%, Inne: %.1f%%}\"\n", tcp_percent, udp_percent, other_percent);
    fprintf(gp, "set ylabel 'Liczba pakietów'\n");
    fprintf(gp, "set style fill solid 0.8 border -1\n");
    fprintf(gp, "set boxwidth 0.5\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set grid ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "unset key\n");

    fprintf(gp, "plot '-' using 0:2:xtic(1) with boxes lc rgb '#2ca02c'\n");
    fprintf(gp, "TCP %u\n", tcp_pkts);
    fprintf(gp, "UDP %u\n", udp_pkts);
    fprintf(gp, "Inne %u\n", other_pkts);
    fprintf(gp, "e\n");

    int status = pclose(gp);
    return (status == 0) ? 0 : -1;
}

int generate_size_chart(const char* output_png, uint32_t sz1, uint32_t sz2, uint32_t sz3, uint32_t sz4, uint32_t sz5, uint32_t sz6){
    
    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Nie udało się uruchomić programu gnuplot");
        return -1;
    }

    fprintf(gp, "set terminal pngcairo size 1000,620 enhanced font 'Sans,13'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Histogram rozmiarów pakietów'\n");
    fprintf(gp, "set ylabel 'Liczba pakietów'\n");
    fprintf(gp, "set style fill solid 0.8 border -1\n");
    fprintf(gp, "set boxwidth 0.5\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set grid ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "unset key\n");

    fprintf(gp, "plot '-' using 0:2:xtic(1) with boxes lc rgb '#2ca02c'\n");
    fprintf(gp, "0-64B %u\n", sz1);
    fprintf(gp, "65-256B %u\n", sz2);
    fprintf(gp, "256-512B %u\n", sz3);
    fprintf(gp, "513-1024B %u\n", sz4);
    fprintf(gp, "1025-1518B %u\n", sz5);
    fprintf(gp, "1518B< %u\n", sz6);
    fprintf(gp, "e\n");

    int status = pclose(gp);
    return (status == 0) ? 0 : -1;
}

int generate_protocol_throughput_chart(const char *output_png, const double *times,
                                       const double *tcp, const double *udp,
                                       const double *other, size_t count) {
    if (count == 0) return -1;

    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Nie udało się uruchomić programu gnuplot");
        return -1;
    }

    fprintf(gp, "set terminal pngcairo size 1000,620 enhanced font 'Sans,13'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Przepustowość według protokołu'\n");
    fprintf(gp, "set xlabel 'Czas od początku przechwytywania [s]'\n");
    fprintf(gp, "set ylabel 'Przepustowość [KB/s]'\n");
    fprintf(gp, "set grid xtics ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set key top right opaque box\n");
    fprintf(gp, "plot '-' using 1:2 with linespoints lw 2 title 'TCP', "
                "'-' using 1:2 with linespoints lw 2 title 'UDP', "
                "'-' using 1:2 with linespoints lw 2 title 'Inne'\n");

    for (size_t i = 0; i < count; i++) fprintf(gp, "%.6f %.2f\n", times[i], tcp[i]);
    fprintf(gp, "e\n");
    for (size_t i = 0; i < count; i++) fprintf(gp, "%.6f %.2f\n", times[i], udp[i]);
    fprintf(gp, "e\n");
    for (size_t i = 0; i < count; i++) fprintf(gp, "%.6f %.2f\n", times[i], other[i]);
    fprintf(gp, "e\n");

    return (pclose(gp) == 0) ? 0 : -1;
}

int generate_top_hosts_chart(const char *output_png, const host_stat_t *hosts, size_t count) {
    if (count == 0) return -1;

    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Nie udało się uruchomić programu gnuplot");
        return -1;
    }

    size_t limit = count < 10 ? count : 10;

    fprintf(gp, "set terminal pngcairo size 1000,620 enhanced font 'Sans,13'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Najaktywniejsze hosty'\n");
    fprintf(gp, "set ylabel 'Przesłane bajty'\n");
    fprintf(gp, "set style fill solid 0.8 border -1\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set boxwidth 0.5\n");
    fprintf(gp, "set grid ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "set xtics (");
    for (size_t i = 0; i < limit; i++) {
        fprintf(gp, "%s\"Host %zu\" %zu", i == 0 ? "" : ", ", i + 1, i);
    }
    fprintf(gp, ")\n");
    fprintf(gp, "unset key\n");
    fprintf(gp, "plot '-' using 0:2 with boxes lc rgb '#2ca02c'\n");
    for (size_t i = 0; i < limit; i++) {
        fprintf(gp, "\"%s\" %lu\n", hosts[i].ip, hosts[i].bytes);
    }
    fprintf(gp, "e\n");

    return (pclose(gp) == 0) ? 0 : -1;
}
