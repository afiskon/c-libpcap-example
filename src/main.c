/*
 * eaxsniff - libpcap usage example
 * (c) Aleksander Alekseev 2016 | http://eax.me/
 */

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "include/net_headers.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// TODO: support text only output, use argp
// TODO: test in IPv6 network

#define UNUSED(x) ((void)(x))

#define PRINT_BYTES_PER_LINE 16

static void
print_data_hex(const uint8_t* data, int size)
{
    UNUSED(data);
    UNUSED(size);

    int offset = 0;
    int nlines = size / PRINT_BYTES_PER_LINE;
    if(nlines * PRINT_BYTES_PER_LINE < size)
        nlines++;

    printf("        ");

    for(int i = 0; i < PRINT_BYTES_PER_LINE; i++)
        printf("%02X ", i);

    printf("\n\n");

    for(int line = 0; line < nlines; line++)
    {
        printf("%04X    ", offset);
        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf("   ");
            else
                printf("%02X ", data[offset + j]);
        }

        printf("   ");

        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf(" ");
            else if(data[offset + j] > 31 && data[offset + j] < 128)
                printf("%c", data[offset + j]);
            else
                printf(".");
        }

        offset += PRINT_BYTES_PER_LINE;
        printf("\n");
    }
}

static void
handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr,
                const uint8_t* bytes)
{
    UNUSED(user);

    // struct ethhdr* ethernet_header = (struct ethhdr *)bytes;
    struct iphdr* ip_header = (struct iphdr*)(bytes +
                                              sizeof(struct ethhdr));
    struct sockaddr_in  source, dest;

	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char source_ip[128];
    char dest_ip[128];
    strncpy(source_ip, inet_ntoa(source.sin_addr), sizeof(source_ip));
    strncpy(dest_ip, inet_ntoa(dest.sin_addr), sizeof(dest_ip));

    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;
    char* next_header = (char*)ip_header + ip_header_size;

    if(ip_header->protocol == IP_HEADER_PROTOCOL_TCP)
    {
        struct tcphdr* tcp_header = (struct tcphdr*)next_header;
        source_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
        int tcp_header_size = tcp_header->doff * 4;
        data_size = hdr->len - sizeof(struct ethhdr) -
                        ip_header_size - tcp_header_size;
    }
    else if(ip_header->protocol == IP_HEADER_PROTOCOL_UDP)
    {
        struct udphdr* udp_header = (struct udphdr*)next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) -
                        ip_header_size - sizeof(struct udphdr);
    }

    printf("\n%s:%d -> %s:%d, %d (0x%x) bytes\n\n",
        source_ip, source_port, dest_ip, dest_port,
        data_size, data_size);

    if(data_size > 0)
    {
        int headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }
}

void
list_devs()
{
	int errcode;
	pcap_if_t *alldevs, *currdev;
	char errbuff[PCAP_ERRBUF_SIZE];

	errcode = pcap_findalldevs(&alldevs, errbuff);
	if(errcode != 0)
	{
		fprintf(stderr, "findalldevs - error: %s\n", errbuff);
		return;
	}

	currdev = alldevs;

	while(currdev)
	{
		printf("%s\t%s\n", currdev->name,
			currdev->description ? currdev->description : "(no description)");
		currdev = currdev->next;
	}

	if(alldevs)
		pcap_freealldevs(alldevs);
}

int
main(int argc, char* argv[])
{
    int res;

    if((argc < 3) && !((argc == 2) && (strcmp(argv[1], "--list-devs") == 0)))
    {
        printf("Usage: %s device filter\n"
               "       %s --list-devs\n",
               argv[0], argv[0]);
        printf("Example: %s eth0 'udp src or dst port 53'\n", argv[0]);
        printf("%s\n", pcap_lib_version());
        return 1;
    }

	if(argc == 2)
	{
		list_devs();
		return 0;
	}

    const char* device = argv[1];
    const char* filter = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(device, 65536, 1, 0, errbuf);
    if(pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filterprog;
    res = pcap_compile(pcap, &filterprog, filter, 0,
                       PCAP_NETMASK_UNKNOWN);
    if(res != 0)
    {
        fprintf(stderr, "pcap_compile failed: %s\n",
                pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }

    res = pcap_setfilter(pcap, &filterprog);
    if(res != 0)
    {
        fprintf(stderr, "pcap_setfilter failed: %s\n",
                pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }

    printf("Listening %s, filter: %s...\n", device, filter);

    res = pcap_loop(pcap, -1, handle_packet, NULL);
    printf("pcap_loop returned %d\n", res);

    pcap_close(pcap);
    return 0;
}

