/**
 * Originally based on udpdump.c example from WinPcap
 *
 * When using GCC, use C99 with GNU extensions: -std=gnu99
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include <pcap/pcap.h>

/* max of 9 players excluding server */
#define MAX_SUBS 9

#define ECHO_REQUEST 8
#define IPV4_ADDR_OCTETS 4
#define MAC_ADDR_OCTETS 6

/* Ethernet II header */
struct ether_header_t {
	uint8_t dst[MAC_ADDR_OCTETS];
	uint8_t src[MAC_ADDR_OCTETS];
	uint16_t type;
};

/* IPv4 header */
struct ip_header_t {
	uint8_t	ver_ihl;		// Version (4 bits) + Header length (4 bits)
	uint8_t	ds;			// DiffServ code point
	uint16_t len;			// Total length
	uint16_t id;			// Identification
	uint16_t flags_off;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	ttl;			// Time to live
	uint8_t	proto;			// Protocol
	uint16_t checksum;			// Header checksum
	uint8_t src[IPV4_ADDR_OCTETS];		// Source address
	uint8_t dst[IPV4_ADDR_OCTETS];		// Destination address
	uint32_t op_pad;			// Option + Padding
};

/* ICMP header */
struct icmp_header_t {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
};

/*
 * Use a global variable for the capture handle
 * because there's no way of passing this handle
 * to the callback function (packet_handler).
 */
static pcap_t *capture;

/* function declarations */
pcap_if_t *select_dev(pcap_if_t *alldevs);
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);


int main(void)
{
	int ret = 0;

	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE] = "";

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	if (alldevs == NULL) {
		printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
		return -1;
	}

	pcap_if_t *dev = select_dev(alldevs);

	/* Open the capture */
	capture = pcap_open_live(dev->name,	// name of the device
							 65535,			// portion of the packet to capture.
							 // 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							);

	if (strlen(errbuf))
		fprintf(stderr, "\nWARNING: %s\n", errbuf);

	if (capture == NULL) {
		fprintf(stderr, "\nUnable to open the capture. It is not supported by libpcap/WinPcap.\n");
		ret = -1;
		goto free_alldevs;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(capture) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		ret = -1;
		goto close_handle;
	}

	char packet_filter[] = "(udp src and dst port 6112 and ether dst FF:FF:FF:FF:FF:FF) or icmp";
	struct bpf_program fcode;

	/* compile the filter */
	if (pcap_compile(capture, &fcode, packet_filter, 1, 0) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		ret = -1;
		goto close_handle;
	}

	/* set the filter */
	if (pcap_setfilter(capture, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		ret = -1;
		goto close_handle;
	}

	printf("\nListening on %s...\n", (dev->description) ? dev->description : dev->name);

	/* start the capture */
	pcap_loop(capture, 0, packet_handler, NULL);

	/* cleanup */
close_handle:
	pcap_close(capture);
free_alldevs:
	pcap_freealldevs(alldevs);

	return ret;
}

pcap_if_t *select_dev(pcap_if_t *alldevs)
{
	pcap_if_t *dev;
	int dev_num = 0;

	/* Print the list */
	for (dev = alldevs; dev != NULL; dev = dev->next) {
		printf("%d. %s", ++dev_num, dev->name);
		if (dev->description)
			printf(" (%s)", dev->description);
		printf("\n");
	}

	int sel_dev_num;
	uint8_t error;
	/* Check if the user specified a valid capture */
	do {
		printf("Enter the interface number (1-%d): ", dev_num);
		scanf("%d", &sel_dev_num); // too lazy to change this :P
		error = sel_dev_num < 1 || sel_dev_num > dev_num;
		if (error)
			printf("\nAdapter number out of range.\n");
	} while (error);

	/* Jump to the selected capture */
	dev = alldevs;
	for (dev_num = 1; dev_num < sel_dev_num; dev_num++)
		dev = dev->next;

	return dev;
}

void copy_octets(uint8_t dst[], uint8_t src[], uint8_t octets)
{
	uint8_t i;

	for (i = 0; i < octets; i++)
		dst[i] = src[i];
}

int equal_octets(uint8_t a[], uint8_t b[], uint8_t octets)
{
	uint8_t i, matches = 0;

	for (i = 0; i < octets; i++) {
		if (a[i] == b[i])
			matches++;
	}

	return matches == octets;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
	/* array of subscribers and the current number of subscribers */
	static uint8_t subscribers[MAC_ADDR_OCTETS][MAX_SUBS];
	static uint8_t num_subs = 0;

	/* get pointer to the IP header */
	struct ip_header_t *ip = (struct ip_header_t *)(pkt_data + sizeof(struct ether_header_t));
	/* calculate the IP header length */
	uint32_t ip_len = (ip->ver_ihl & 0xF) * 4;
	/* get pointer to the ICMP header (ICMP packets only) */
	struct icmp_header_t *icmp = (struct icmp_header_t *)((uint8_t *)ip + ip_len);

	/* proceeed only if: UDP or (ICMP echo request and num_subs < MAX_SUBS) */
	if (!(ip->proto == 17 || (ip->proto == 1 && icmp->type == ECHO_REQUEST && num_subs < MAX_SUBS)))
		return;

	/* frame header */
	struct ether_header_t *ether = (struct ether_header_t *)pkt_data;
	uint8_t i;

	struct tm *ltime = localtime(&header->ts.tv_sec);
	char timestr[16];

	/* convert the timestamp to readable format */
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* UDP is protocol 17 */
	if (ip->proto == 17) {
		printf("%s\tSeen war3 broadcast\n", timestr);
		/* Send the war3 broadcast to all subscribers */
		for (i = 0; i < num_subs; i++) {
			/* Set destination MAC address */
			copy_octets(ether->dst, subscribers[i], MAC_ADDR_OCTETS);
			/* Inject the modified packet back to the device */
			pcap_sendpacket(capture, pkt_data, header->len);
		}
	} else {
		/* Loop through all the existing subscriber MACs and check for duplicates */
		for (i = 0; i < num_subs; i++) {
			if (equal_octets(subscribers[i], ether->src, MAC_ADDR_OCTETS))
				return;
		}
		/* Save the MAC address of the source of the ICMP echo request */
		copy_octets(subscribers[num_subs], ether->src, MAC_ADDR_OCTETS);
		num_subs++;

		printf("%s\tAdded %02X:%02X:%02X:%02X:%02X:%02X to list\n", timestr,
			   ether->src[0], ether->src[1], ether->src[2],
			   ether->src[3], ether->src[4], ether->src[5]);
	}
}
