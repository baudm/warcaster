#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include <pcap/pcap.h>

// max of 9 players excluding server
#define MAX_SUBS 9
#define ECHO_REQUEST 8
#define IP_ADDR_OCTETS 4
#define MAC_ADDR_OCTETS 6

struct ether_header_t {
    uint8_t dmac[MAC_ADDR_OCTETS];
    uint8_t smac[MAC_ADDR_OCTETS];
    uint16_t type;
};

/* IPv4 header */
struct ip_header_t {
	uint8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	uint8_t	tos;			// Type of service
	uint16_t tlen;			// Total length
	uint16_t identification; // Identification
	uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	ttl;			// Time to live
	uint8_t	proto;			// Protocol
	uint16_t crc;			// Header checksum
	uint8_t saddr[IP_ADDR_OCTETS];		// Source address
	uint8_t daddr[IP_ADDR_OCTETS];		// Destination address
	uint32_t op_pad;			// Option + Padding
};

struct icmp_header_t {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

/* prototype of the packet handler */
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
static pcap_t *adhandle;

int main(void)
{
	pcap_if_t *alldevs, *dev;
	int dev_num = 0, sel_dev_num;
	char errbuf[PCAP_ERRBUF_SIZE] = "";

	char packet_filter[] = "(udp src and dst port 6112 and ether dst FF:FF:FF:FF:FF:FF) or icmp";
	struct bpf_program fcode;

	int ret = 0;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	if (alldevs == NULL) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/* Print the list */
	for (dev = alldevs; dev != NULL; dev = dev->next)
		printf("%d. %s (%s)\n", ++dev_num, dev->name, dev->description);

    uint8_t error;
    /* Check if the user specified a valid adapter */
    do {
        printf("Enter the interface number (1-%d): ", dev_num);
        scanf("%d", &sel_dev_num);
        error = sel_dev_num < 1 || sel_dev_num > dev_num;
        if (error)
            printf("\nAdapter number out of range.\n");
    } while (error);

	/* Jump to the selected adapter */
	for (dev = alldevs, dev_num = 0; dev_num < sel_dev_num - 1; dev = dev->next, dev_num++);

	/* Open the adapter */
	adhandle = pcap_open_live(dev->name,	// name of the device
							 65535,			// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 );

    if (strlen(errbuf))
        fprintf(stderr, "\nWARNING: %s\n", errbuf);

	if (adhandle == NULL) {
		fprintf(stderr, "\nUnable to open the adapter.  is not supported by WinPcap\n");
		ret = -1;
		goto free_alldevs;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		ret = -1;
		goto close_handle;
	}

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, 0) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		ret = -1;
		goto close_handle;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		ret = -1;
		goto close_handle;
	}

	printf("\nListening on %s...\n", dev->description);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

close_handle:
    pcap_close(adhandle);
free_alldevs:
	pcap_freealldevs(alldevs);

	return ret;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
	static uint8_t subscribers[MAC_ADDR_OCTETS][MAX_SUBS];
    static uint8_t subs_len = 0;

    struct ip_header_t *ip;
    uint32_t ip_len;
	struct icmp_header_t *icmp;

	/* retrieve the position of the ip header */
	ip = (struct ip_header_t *)(pkt_data + sizeof(struct ether_header_t));
	/* retrieve the IP header length */
    ip_len = (ip->ver_ihl & 0xF) * 4;
    icmp = (struct icmp_header_t *)((uint8_t *)ip + ip_len);

    // execute only if: UDP or (ICMP echo request and subs_len < MAX_SUBS)
    if (!(ip->proto == 17 || (icmp->type == ECHO_REQUEST && subs_len < MAX_SUBS)))
        return;

    // frame header
    struct ether_header_t *ether = (struct ether_header_t *)pkt_data;
    uint8_t i ,j;

    struct tm *ltime;
    char timestr[16];

    /* convert the timestamp to readable format */
    ltime = localtime(&header->ts.tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    // UDP is protocol 17
	if (ip->proto == 17) {
	    /* print timestamp and length of the packet */
        printf("%s\tSeen war3 broadcast\n", timestr);

        for (i = 0; i < subs_len; i++) {
            // set destination MAC address
            for (j = 0; j < MAC_ADDR_OCTETS; j++)
                ether->dmac[j] = subscribers[i][j];
            pcap_sendpacket(adhandle, pkt_data, header->len);
        }

	} else {
        uint8_t matches;

        // loop through all the existing subscriber MACs and check for duplicates
	    for (i = 0; i < subs_len; i++) {
	        matches = 0;
	        for (j = 0; j < MAC_ADDR_OCTETS; j++) {
	            if (subscribers[i][j] == ether->smac[j])
                    matches++;
	        }
	        // if all six octets match, this is a duplicate
	        // no need to add it, just return.
	        if (matches == MAC_ADDR_OCTETS)
                return;
	    }

        for (j = 0; j < MAC_ADDR_OCTETS; j++)
            subscribers[subs_len][j] = ether->smac[j];
        subs_len++;
        printf("%s\tAdded %02X:%02X:%02X:%02X:%02X:%02X to list\n", timestr,
               ether->smac[0], ether->smac[1], ether->smac[2],
               ether->smac[3], ether->smac[4], ether->smac[5]);
	}
}
