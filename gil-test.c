#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_SIZE 14
#define MAX_PAYLOAD_PRINT 20

typedef struct {
    unsigned char destMac[6];
    unsigned char srcMac[6];
    unsigned short etherType;
} EthernetHeader;

typedef struct {
    unsigned char versionAndIHL;
    unsigned char typeOfService;
    unsigned short totalLength;
    unsigned short identification;
    unsigned short flagsAndFragmentOffset;
    unsigned char timeToLive;
    unsigned char protocol;
    unsigned short headerChecksum;
    struct in_addr srcIP;
    struct in_addr destIP;
} IPHeader;

typedef struct {
    unsigned short srcPort;
    unsigned short destPort;
    unsigned int sequenceNumber;
    unsigned int acknowledgementNumber;
    unsigned char dataOffsetAndFlags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgentPointer;
} TCPHeader;

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void printEthernetHeader(const EthernetHeader* ethHeader) {
    printf("==================== Ethernet Header ====================\n");
    printf("Source MAC      : %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethHeader->srcMac[0], ethHeader->srcMac[1], ethHeader->srcMac[2],
           ethHeader->srcMac[3], ethHeader->srcMac[4], ethHeader->srcMac[5]);
    printf("Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethHeader->destMac[0], ethHeader->destMac[1], ethHeader->destMac[2],
           ethHeader->destMac[3], ethHeader->destMac[4], ethHeader->destMac[5]);
    printf("=========================================================\n");
}

void printIPHeader(const IPHeader* ipHeader) {
    printf("======================= IP Header =======================\n");
    printf("Source IP       : %s\n", inet_ntoa(ipHeader->srcIP));
    printf("Destination IP  : %s\n", inet_ntoa(ipHeader->destIP));
    printf("=========================================================\n");
}

void printTCPHeader(const TCPHeader* tcpHeader) {
    printf("====================== TCP Header =======================\n");
    printf("Source Port     : %d\n", ntohs(tcpHeader->srcPort));
    printf("Destination Port: %d\n", ntohs(tcpHeader->destPort));
    printf("=========================================================\n");
}

void printPayload(const u_char* payload, int length) {
    printf("======================= Payload =========================\n");
    printf("First %d bytes:\n", MAX_PAYLOAD_PRINT);
    for (int i = 0; i < MAX_PAYLOAD_PRINT && i < length; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (length > MAX_PAYLOAD_PRINT) printf("\n(Payload truncated...)");
    printf("\n=========================================================\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    printf("Starting packet capture on interface: %s\n", param.dev_);
    printf("Press Ctrl+C to stop the capture.\n\n");

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("\n================ Packet Captured ================\n");
        printf("Packet length: %u bytes\n", header->caplen);

        const EthernetHeader* ethHeader = (EthernetHeader*)packet;
        printEthernetHeader(ethHeader);

        if (ntohs(ethHeader->etherType) == 0x0800) { // IPv4
            const IPHeader* ipHeader = (IPHeader*)(packet + ETHERNET_HEADER_SIZE);
            printIPHeader(ipHeader);

            if (ipHeader->protocol == IPPROTO_TCP) {
                const TCPHeader* tcpHeader = (TCPHeader*)((u_char*)ipHeader + (ipHeader->versionAndIHL & 0x0F) * 4);
                printTCPHeader(tcpHeader);

                int tcpHeaderLength = (tcpHeader->dataOffsetAndFlags >> 4) * 4;
                const u_char* payload = (u_char*)tcpHeader + tcpHeaderLength;
                int payloadLength = ntohs(ipHeader->totalLength) - ((ipHeader->versionAndIHL & 0x0F) * 4) - tcpHeaderLength;

                if (payloadLength > 0) {
                    printPayload(payload, payloadLength);
                }
            }
        }
    }

    pcap_close(pcap);
    return 0;
}