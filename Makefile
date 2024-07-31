# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra

# Libraries
LDLIBS += -lpcap

# Targets
all: pcap-test

# Build pcap-test
pcap-test: gil-test.o
	$(CC) $(CFLAGS) -o pcap-test gil-test.o $(LDLIBS)

# Compile gil-test.c
gil-test.o: gil-test.c
	$(CC) $(CFLAGS) -c gil-test.c

# Clean build files
clean:
	rm -f pcap-test *.o

