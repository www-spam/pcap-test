#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "pcap-test.h"

#define MAX_PAYLOAD_PRINT 20


typedef struct {
	char* dev;
} Param;

bool parse(int argc, char* argv[], Param* param) {
	param->dev = argv[1];
	return true;
}

void print_mac(const char* label, const uint8_t* mac) {
	printf("%s %02X:%02X:%02X:%02X:%02X:%02X\n",
		   label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char* data, int len) {
	printf("Payload (max %d bytes): ", MAX_PAYLOAD_PRINT);
	if (len <= 0) {
		printf("-\n\n");
		return;
	}

	for (int i = 0; i < len && i < MAX_PAYLOAD_PRINT; i++) {
		printf("%02X ", data[i]);
	}
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	Param param;

	if (!parse(argc, argv, &param))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(param.dev, BUFSIZ, 1, 1000, errbuf);
	if (!handle) {
		fprintf(stderr, "pcap_open_live(%s) failed: %s\n", param.dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
			break;
		}

		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth->ether_type) != 0x0800) continue; // IPv4 아닌 경우 skip

		struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		if (ip->ip_p != 6) continue; // TCP가 아닌 경우 skip

		int ip_header_len = ip->ip_hl * 4;
		struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((u_char*)ip + ip_header_len);
		int tcp_header_len = tcp->th_off * 4;

		const u_char* payload = (u_char*)tcp + tcp_header_len;
		int total_ip_len = ntohs(ip->ip_len);
		int payload_len = total_ip_len - ip_header_len - tcp_header_len;

		printf("================= TCP Packet =================\n");
		print_mac("Src MAC:", eth->ether_shost);
		print_mac("Dst MAC:", eth->ether_dhost);
		printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
		printf("Dst IP : %s\n", inet_ntoa(ip->ip_dst));
		printf("Src Port : %u\n", ntohs(tcp->th_sport));
		printf("Dst Port : %u\n", ntohs(tcp->th_dport));

		int max_len_from_cap = header->caplen - (payload - packet);
		int real_payload_len = (payload_len < max_len_from_cap) ? payload_len : max_len_from_cap;

		print_payload(payload, real_payload_len);
	}

	pcap_close(handle);
	return 0;
}
