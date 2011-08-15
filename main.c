/**
 * war3relay - relays Warcraft III server broadcast to specific hosts on the LAN
 *
 * Copyright (C) 2011  Darwin M. Bautista <djclue917@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * NOTES:
 *   1. Device selection and program flow are inspired by WinPcap examples
 *   2. When using GCC, use C99 with GNU extensions: -std=gnu99
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
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
	uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
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
void break_loop(int param)
{
	pcap_breakloop(capture);
}


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
	capture = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);

	if (strlen(errbuf))
		fprintf(stderr, "\nWARNING: %s\n", errbuf);

	if (capture == NULL) {
		fprintf(stderr, "\nUnable to open the capture. It is not supported by libpcap/WinPcap.\n");
		pcap_freealldevs(alldevs);
		return -1;
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
	/* alldevs is no longer needed at this point */
	pcap_freealldevs(alldevs);

	/* Make Ctrl-C break the loop so that we can still cleanup before terminating */
	signal(SIGINT, break_loop);

	/* start the capture */
	pcap_loop(capture, 0, packet_handler, NULL);

	/* cleanup */
close_handle:
	pcap_close(capture);

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

	int sel_dev_num = 0;
	uint8_t error;
	/* Check if the user specified a valid device */
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
	struct ether_header_t *ether;
	uint8_t i;

	struct tm *ltime = localtime(&header->ts.tv_sec);
	char timestr[9];

	/* convert the timestamp to readable format */
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* UDP is protocol 17 */
	if (ip->proto == 17) {
		/* Use a VLA to hold the data of the modified packet */
		uint8_t new_pkt_data[header->len];

		/* create a copy of the captured packet because it's not supposed to be modified */
		memcpy(new_pkt_data, pkt_data, header->len);
		ether = (struct ether_header_t *)new_pkt_data;

		printf("%s\tSeen war3 broadcast\n", timestr);
		/* Send the war3 broadcast to all subscribers */
		for (i = 0; i < num_subs; i++) {
			/* Set destination MAC address */
			memcpy(ether->dst, subscribers[i], MAC_ADDR_OCTETS);
			/* Inject the modified packet back to the device */
			pcap_sendpacket(capture, new_pkt_data, header->len);
		}
	} else {
		ether = (struct ether_header_t *)pkt_data;
		/* Loop through all the existing subscriber MACs and check for duplicates */
		for (i = 0; i < num_subs; i++) {
			if (memcmp(subscribers[i], ether->src, MAC_ADDR_OCTETS) == 0)
				return;
		}
		/* Save the MAC address of the source of the ICMP echo request */
		memcpy(subscribers[num_subs], ether->src, MAC_ADDR_OCTETS);
		num_subs++;

		printf("%s\tAdded %02X:%02X:%02X:%02X:%02X:%02X to list\n", timestr,
			   ether->src[0], ether->src[1], ether->src[2],
			   ether->src[3], ether->src[4], ether->src[5]);
	}
}
