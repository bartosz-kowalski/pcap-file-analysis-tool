#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "pdfgen.h"
#include "report.h"

#define PAGE_MARGIN 40.0f
#define DARK_BLUE PDF_RGB(24, 48, 82)
#define ACCENT_BLUE PDF_RGB(34, 111, 168)
#define LIGHT_BLUE PDF_RGB(232, 241, 248)
#define DARK_GREY PDF_RGB(75, 85, 99)

static int add_text_top(struct pdf_doc *pdf, struct pdf_object *page,
                        const char *text, float size, float x, float top,
                        uint32_t colour) {
    float page_height = pdf_page_height(page);
    return pdf_add_text(pdf, page, text, size, x,
                        page_height - top - size, colour);
}

static int add_page_header(struct pdf_doc *pdf, struct pdf_object *page,
                           const char *title, size_t page_number) {
    char page_label[48];
    snprintf(page_label, sizeof(page_label), "Strona %zu", page_number);
    float page_width = pdf_page_width(page);
    float page_height = pdf_page_height(page);

    if (add_text_top(pdf, page, TITLE, 9, PAGE_MARGIN, 22, DARK_GREY) < 0 ||
        add_text_top(pdf, page, title, 19, PAGE_MARGIN, 48, DARK_BLUE) < 0 ||
        pdf_add_line(pdf, page, PAGE_MARGIN, page_height - 78,
                     page_width - PAGE_MARGIN, page_height - 78,
                     1, ACCENT_BLUE) < 0 ||
        add_text_top(pdf, page, page_label, 8,
                     page_width - PAGE_MARGIN - 45, 22, DARK_GREY) < 0) {
        return -1;
    }
    return 0;
}

static struct pdf_object *append_report_page(struct pdf_doc *pdf,
                                              const char *title,
                                              size_t page_number) {
    struct pdf_object *page = pdf_append_page(pdf);
    if (page == NULL || add_page_header(pdf, page, title, page_number) < 0) {
        return NULL;
    }
    return page;
}

static struct pdf_object *append_chart_page(struct pdf_doc *pdf,
                                             const char *title,
                                             size_t page_number) {
    struct pdf_object *page = pdf_append_page(pdf);
    if (page == NULL ||
        pdf_page_set_size(pdf, page, PDF_A4_HEIGHT, PDF_A4_WIDTH) < 0 ||
        add_page_header(pdf, page, title, page_number) < 0) {
        return NULL;
    }
    return page;
}

static void report_pdf_error(struct pdf_doc *pdf, const char *operation) {
    const char *detail = pdf != NULL ? pdf_get_err(pdf, NULL) : NULL;
    fprintf(stderr, "Nie udało się %s%s%s\n", operation,
            detail != NULL ? ": " : "",
            detail != NULL ? detail : "");
}

static const char *find_polish_font(void) {
    static const char *const paths[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf"
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], R_OK) == 0) return paths[i];
    }
    return NULL;
}

static int add_table_heading(struct pdf_doc *pdf, struct pdf_object *page,
                             float top, const char *left, const char *right) {
    if (pdf_add_rectangle(pdf, page, PAGE_MARGIN,
                          PDF_A4_HEIGHT - top - 20,
                          PDF_A4_WIDTH - 2 * PAGE_MARGIN, 20, 0,
                          LIGHT_BLUE) < 0 ||
        add_text_top(pdf, page, left, 9, PAGE_MARGIN + 6, top + 5,
                     DARK_BLUE) < 0 ||
        add_text_top(pdf, page, right, 9,
                     PDF_A4_WIDTH - PAGE_MARGIN - 120, top + 5,
                     DARK_BLUE) < 0) {
        return -1;
    }
    return 0;
}

int generate_report(const char *output_path,
                    const packet_data *packets, const header_data *hdr,
                    const host_stat_t *hosts, size_t host_count,
                    const port_stat_t *ports, size_t port_count,
                    const flow_t *flows, size_t flow_count,
                    const char *const *images, size_t image_count,
                    const traffic_summary_t *summary) {
    if (output_path == NULL || hdr == NULL || summary == NULL ||
        (hdr->packet_no > 0 && packets == NULL) ||
        (host_count > 0 && hosts == NULL) ||
        (port_count > 0 && ports == NULL) ||
        (flow_count > 0 && flows == NULL)) {
        fprintf(stderr, "Nie można wygenerować raportu: nieprawidłowe dane wejściowe.\n");
        return -1;
    }

    time_t now = time(NULL);
    struct tm local_time;
    char date[32] = "nieznana";
    char pdf_date[32] = "";
    if (localtime_r(&now, &local_time) != NULL) {
        strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &local_time);
        strftime(pdf_date, sizeof(pdf_date), "%Y%m%d%H%M%S", &local_time);
    }

    struct pdf_info info = {
        .author = AUTHOR,
        .creator = CREATOR,
        .date = "",
        .producer = CREATOR,
        .subject = SUBJECT,
        .title = TITLE
    };
    snprintf(info.date, sizeof(info.date), "%s", pdf_date);

    struct pdf_doc *pdf = pdf_create(PDF_A4_WIDTH, PDF_A4_HEIGHT, &info);
    if (pdf == NULL) {
        fprintf(stderr, "Nie udało się utworzyć dokumentu PDF.\n");
        return -1;
    }

    const char *font_path = find_polish_font();
    if (font_path == NULL || pdf_set_font_ttf(pdf, font_path) == NULL) {
        fprintf(stderr, "Nie znaleziono czcionki TrueType obsługującej polskie znaki.\n");
        pdf_destroy(pdf);
        return -1;
    }

    int result = -1;
    size_t page_number = 1;
    struct pdf_object *page = pdf_append_page(pdf);
    if (page == NULL) {
        report_pdf_error(pdf, "utworzyć stronę raportu");
        goto cleanup;
    }

    uint32_t tcp_count = 0, udp_count = 0, other_count = 0;
    uint64_t captured_bytes = 0;
    for (uint32_t i = 0; i < hdr->packet_no; i++) {
        captured_bytes += packets[i].original_len;
        uint8_t protocol = packets[i].final_data != NULL
            ? packets[i].final_data->protocol_type
            : 0;
        if (protocol == 6) tcp_count++;
        else if (protocol == 17) udp_count++;
        else other_count++;
    }

    double duration = 0;
    if (hdr->packet_no > 1) {
        duration = get_packet_time(&packets[hdr->packet_no - 1], hdr->sec_micro) -
                   get_packet_time(&packets[0], hdr->sec_micro);
        if (duration < 0) duration = 0;
    }

    if (add_text_top(pdf, page, TITLE, 11, PAGE_MARGIN, 35, ACCENT_BLUE) < 0 ||
        add_text_top(pdf, page, "Raport analizy ruchu sieciowego", 25,
                     PAGE_MARGIN, 75, DARK_BLUE) < 0 ||
        add_text_top(pdf, page, "Podsumowanie pliku PCAP", 14,
                     PAGE_MARGIN, 112, DARK_GREY) < 0 ||
        pdf_add_line(pdf, page, PAGE_MARGIN, PDF_A4_HEIGHT - 145,
                     PDF_A4_WIDTH - PAGE_MARGIN, PDF_A4_HEIGHT - 145,
                     2, ACCENT_BLUE) < 0 ||
        add_text_top(pdf, page, "Data wygenerowania:", 10,
                     PAGE_MARGIN, 165, DARK_GREY) < 0 ||
        add_text_top(pdf, page, date, 10, 160, 165, PDF_BLACK) < 0) {
        report_pdf_error(pdf, "dodać stronę tytułową");
        goto cleanup;
    }

    if (add_table_heading(pdf, page, 205, "Podstawowe informacje", "Wartość") < 0) {
        report_pdf_error(pdf, "dodać podsumowanie");
        goto cleanup;
    }

    const char *labels[] = {
        "Liczba pakietów", "Czas przechwytywania", "Łączny rozmiar pakietów",
        "Protokół TCP", "Protokół UDP", "Pozostałe protokoły",
        "Typ łącza PCAP", "Maksymalny rozmiar pakietu (snaplen)"
    };
    char values[8][64];
    snprintf(values[0], sizeof(values[0]), "%u", hdr->packet_no);
    snprintf(values[1], sizeof(values[1]), "%.6f s", duration);
    snprintf(values[2], sizeof(values[2]), "%llu B",
             (unsigned long long)captured_bytes);
    snprintf(values[3], sizeof(values[3]), "%u", tcp_count);
    snprintf(values[4], sizeof(values[4]), "%u", udp_count);
    snprintf(values[5], sizeof(values[5]), "%u", other_count);
    snprintf(values[6], sizeof(values[6]), "%u", hdr->LinkType);
    snprintf(values[7], sizeof(values[7]), "%u B", hdr->SnapLen);

    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        float top = 232 + (float)i * 23;
        if (add_text_top(pdf, page, labels[i], 10, PAGE_MARGIN + 8,
                         top, PDF_BLACK) < 0 ||
            add_text_top(pdf, page, values[i], 10, 350, top, DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać informacje o przechwytywaniu");
            goto cleanup;
        }
    }

    if (add_table_heading(pdf, page, 430, "Statystyki i wykryte zdarzenia", "Wartość") < 0) {
        report_pdf_error(pdf, "dodać statystyki");
        goto cleanup;
    }

    const char *summary_labels[] = {
        "Unikalne hosty", "Porty", "Sesje", "Średni rozmiar pakietu",
        "Mediana / 95. percentyl pakietu", "Retransmisje TCP",
        "Pakiety TCP poza kolejnością", "Pakiety pofragmentowane",
        "Pakiety DNS", "Pakiety z zerowym oknem TCP",
        "Połączenia TCP zestawione / FIN / RST", "Pakiety SYN bez SYN-ACK"
    };
    char summary_values[12][80];
    snprintf(summary_values[0], sizeof(summary_values[0]), "%zu", summary->host_count);
    snprintf(summary_values[1], sizeof(summary_values[1]), "%zu", summary->port_count);
    snprintf(summary_values[2], sizeof(summary_values[2]), "%zu", summary->flow_count);
    snprintf(summary_values[3], sizeof(summary_values[3]), "%.2f B", summary->avg_packet_size);
    snprintf(summary_values[4], sizeof(summary_values[4]), "%u B / %u B",
             summary->median_packet_size, summary->p95_packet_size);
    snprintf(summary_values[5], sizeof(summary_values[5]), "%u", summary->retransmissions);
    snprintf(summary_values[6], sizeof(summary_values[6]), "%u", summary->out_of_order);
    snprintf(summary_values[7], sizeof(summary_values[7]), "%u", summary->frag_packets);
    snprintf(summary_values[8], sizeof(summary_values[8]), "%u", summary->dns_packets);
    snprintf(summary_values[9], sizeof(summary_values[9]), "%u", summary->zero_window_packets);
    snprintf(summary_values[10], sizeof(summary_values[10]), "%u / %u / %u",
             summary->established, summary->closed_fin, summary->aborted_rst);
    snprintf(summary_values[11], sizeof(summary_values[11]), "%u",
             summary->syn_without_synack);

    for (size_t i = 0; i < sizeof(summary_labels) / sizeof(summary_labels[0]); i++) {
        float top = 456 + (float)i * 21;
        if (add_text_top(pdf, page, summary_labels[i], 9, PAGE_MARGIN + 8,
                         top, PDF_BLACK) < 0 ||
            add_text_top(pdf, page, summary_values[i], 9, 350, top,
                         DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać statystyki analizy");
            goto cleanup;
        }
    }
    if (add_text_top(pdf, page,
                     "Uwaga: liczby hostów i portów obejmują wystąpienia po obu stronach pakietu.",
                     8, PAGE_MARGIN, 730, DARK_GREY) < 0) {
        report_pdf_error(pdf, "dodać objaśnienie statystyk");
        goto cleanup;
    }

    page_number++;
    page = append_report_page(pdf, "Najaktywniejsze hosty i porty", page_number);
    if (page == NULL) {
        report_pdf_error(pdf, "utworzyć stronę hostów i portów");
        goto cleanup;
    }

    if (add_table_heading(pdf, page, 100, "Host", "Bajty / pakiety") < 0) {
        report_pdf_error(pdf, "dodać tabelę hostów");
        goto cleanup;
    }
    size_t host_limit = host_count < 15 ? host_count : 15;
    for (size_t i = 0; i < host_limit; i++) {
        char value[80];
        snprintf(value, sizeof(value), "%llu B / %u",
                 (unsigned long long)hosts[i].bytes, hosts[i].packs);
        if (add_text_top(pdf, page, hosts[i].ip, 9, PAGE_MARGIN + 8,
                         128 + (float)i * 17, PDF_BLACK) < 0 ||
            add_text_top(pdf, page, value, 9, 400,
                         128 + (float)i * 17, DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać wpis hosta");
            goto cleanup;
        }
    }

    if (add_table_heading(pdf, page, 410, "Port / protokół", "Bajty / pakiety") < 0) {
        report_pdf_error(pdf, "dodać tabelę portów");
        goto cleanup;
    }
    size_t port_limit = port_count < 15 ? port_count : 15;
    for (size_t i = 0; i < port_limit; i++) {
        char label[80], value[80];
        const char *protocol = ports[i].protocol == 6 ? "TCP" :
                               ports[i].protocol == 17 ? "UDP" : "inny";
        snprintf(label, sizeof(label), "%u / %s", ports[i].port, protocol);
        snprintf(value, sizeof(value), "%llu B / %u",
                 (unsigned long long)ports[i].bytes, ports[i].packs);
        if (add_text_top(pdf, page, label, 9, PAGE_MARGIN + 8,
                         438 + (float)i * 17, PDF_BLACK) < 0 ||
            add_text_top(pdf, page, value, 9, 400,
                         438 + (float)i * 17, DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać wpis portu");
            goto cleanup;
        }
    }
    if (host_limit == 0 && port_limit == 0 &&
        add_text_top(pdf, page, "Brak danych hostów i portów.", 10,
                     PAGE_MARGIN, 135, DARK_GREY) < 0) {
        report_pdf_error(pdf, "dodać informację o braku hostów i portów");
        goto cleanup;
    }

    page_number++;
    page = append_report_page(pdf, "Sesje sieciowe", page_number);
    if (page == NULL) {
        report_pdf_error(pdf, "utworzyć stronę sesji");
        goto cleanup;
    }
    if (add_table_heading(pdf, page, 100, "Sesja", "Pakiety / bajty / czas") < 0) {
        report_pdf_error(pdf, "dodać tabelę sesji");
        goto cleanup;
    }
    size_t flow_limit = flow_count < 25 ? flow_count : 25;
    for (size_t i = 0; i < flow_limit; i++) {
        char label[140], value[100];
        const char *protocol = flows[i].protocol == 6 ? "TCP" :
                               flows[i].protocol == 17 ? "UDP" : "IP";
        snprintf(label, sizeof(label), "%s:%u  ↔  %s:%u (%s)",
                 flows[i].src_ip, flows[i].src_port,
                 flows[i].dst_ip, flows[i].dst_port, protocol);
        snprintf(value, sizeof(value), "%u / %llu B / %.3f s",
                 flows[i].packs, (unsigned long long)flows[i].bytes,
                 flows[i].t_last - flows[i].t_first);
        if (add_text_top(pdf, page, label, 7.5f, PAGE_MARGIN + 5,
                         128 + (float)i * 23, PDF_BLACK) < 0 ||
            add_text_top(pdf, page, value, 7.5f, 380,
                         128 + (float)i * 23, DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać wpis sesji");
            goto cleanup;
        }
    }
    if (flow_limit == 0 &&
        add_text_top(pdf, page, "Nie wykryto sesji.", 10,
                     PAGE_MARGIN, 130, DARK_GREY) < 0) {
        report_pdf_error(pdf, "dodać informację o braku sesji");
        goto cleanup;
    }
    if (flow_count > flow_limit) {
        char note[96];
        snprintf(note, sizeof(note), "Wyświetlono %zu z %zu sesji.",
                 flow_limit, flow_count);
        if (add_text_top(pdf, page, note, 8, PAGE_MARGIN, 720, DARK_GREY) < 0) {
            report_pdf_error(pdf, "dodać informację o liczbie sesji");
            goto cleanup;
        }
    }

    static const char *const chart_titles[] = {
        "Udział protokołów", "Przepustowość ruchu w czasie",
        "Przepustowość według protokołu", "Najaktywniejsze hosty",
        "Rozkład rozmiarów pakietów"
    };
    size_t chart_count = image_count < sizeof(chart_titles) / sizeof(chart_titles[0])
        ? image_count
        : sizeof(chart_titles) / sizeof(chart_titles[0]);
    for (size_t i = 0; i < chart_count; i++) {
        page_number++;
        page = append_chart_page(pdf, chart_titles[i], page_number);
        if (page == NULL) {
            report_pdf_error(pdf, "utworzyć stronę wykresu");
            goto cleanup;
        }
        float image_width = pdf_page_width(page) - 40;
        float image_height = image_width * 620.0f / 1000.0f;
        if (images == NULL || images[i] == NULL ||
            pdf_add_image_file(pdf, page, 20, 16,
                               image_width, image_height, images[i]) < 0) {
            fprintf(stderr, "Nie udało się dodać wykresu do raportu: %s\n",
                    images != NULL && images[i] != NULL ? images[i] : "(brak ścieżki)");
            if (add_text_top(pdf, page, "Wykres jest niedostępny.", 10,
                             PAGE_MARGIN, 150, DARK_GREY) < 0) {
                report_pdf_error(pdf, "dodać informację o braku wykresu");
                goto cleanup;
            }
        }
    }

    if (pdf_save(pdf, output_path) < 0) {
        report_pdf_error(pdf, "zapisać raport PDF");
        goto cleanup;
    }
    printf("Zapisano raport PDF: %s\n", output_path);
    result = 0;

cleanup:
    pdf_destroy(pdf);
    return result;
}
