# PCAP file analysis tool
This tool parses a `.pcap` file and generates network traffic charts and a Polish PDF report. It is designed for Linux and written in C.
## Prerequisites
Install GCC, GNU Make, `curl`, `gnuplot`, and a TrueType font with Polish character support. The build downloads the `pdfgen` library from GitHub.
## Compilation and usage
To compile the program you need to type
```bash
make clean
make
``` 
inside the terminal, while in the main folder of the application.
To run the program you shuold type:
``` bash
build/program plik.pcap [nazwa_raportu]
```
where:
- `plik.pcap` is the input capture file,
- `nazwa_raportu` is optional; the program generates a Polish PDF report. If omitted, the report uses the input filename with a `.pdf` extension. If supplied without an extension, `.pdf` is appended.