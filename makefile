CC = gcc
CFLAGS = -O2 -Iinclude -Ibuild -g -Wall -Wextra
LDFLAGS = -lm

TARGET = build/program

SRC = src/main.c src/header_parser.c src/packet_parser.c src/ip_parser.c src/plotting.c src/utils.c src/report.c
OBJ = $(SRC:src/%.c=build/%.o) build/pdfgen.o

PDFGEN_URL = https://raw.githubusercontent.com/AndreRenaud/pdfgen/master

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Ensure pdfgen.h exists before compiling your own .c files
build/%.o: src/%.c | build/pdfgen.h
	@mkdir -p build images
	$(CC) $(CFLAGS) -c $< -o $@

# Download pdfgen files into build/ at build time
build/pdfgen.h build/pdfgen.c:
	@mkdir -p build
	curl -sL $(PDFGEN_URL)/pdfgen.h -o build/pdfgen.h
	curl -sL $(PDFGEN_URL)/pdfgen.c -o build/pdfgen.c

# Compile pdfgen.c without -Wall -Wextra so third-party warnings don't clutter your output
build/pdfgen.o: build/pdfgen.c build/pdfgen.h
	$(CC) -O2 -Ibuild -g -c build/pdfgen.c -o $@

clean:
	rm -f build/*.o $(TARGET)

distclean:
	rm -rf build

.PHONY: all clean distclean