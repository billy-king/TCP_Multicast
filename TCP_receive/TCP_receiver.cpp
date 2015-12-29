/******************************************************************************
 * TCP_send.cpp
 * 
 * Send data with TCP protocal
 *
 *      * * *                       * * *
 *    *       *        Data       *       *
 *   *         *  ------------>  *         *
 *  *   Node 1  *               *   Node 2  *
 *   *         *  <------------  *         *
 *    *       *        ACK        *       *
 *      * * *                       * * *
 *  ___________________________________________
 * |                                           |
 * | This is receive side version (for Node 2) |
 * |___________________________________________|
 *
 ******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define MAX_PKT_SIZE 1512
#define DEV "eth0"
#define IP "192.168.197.150"
#define TO_IP "192.168.197.142"

using namespace std;

pcap_t *outdesc;					// for send out
char errbuf[PCAP_ERRBUF_SIZE];		// error buffer for libpcap

// get the ip header from packet
struct ip* get_iph(u_char *packet){
	struct ip *iph = (struct ip*)(packet + sizeof(ethhdr));
	return iph;
}

// get the tcp header from packet
struct tcphdr* get_tcph(u_char *packet){
	struct ip *iph = get_iph(packet);
	struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(ethhdr) + iph->ip_hl*4);
	return tcph;
}

// print out IP and TCP information of the packet 
void print_PKT(u_char *packet){
	static bool isFirst = true;
	if(isFirst){
		printf("%-18s", "Src IP");
		printf("%-18s", "Dst IP");
		printf("%-10s", "Src Port");
		printf("%-10s", "Dst Port");
		printf("%-10s", "SEQ #");
		printf("%-10s", "ACK #");
		printf("%-10s", "Win Size");
		printf("\n");

		isFirst = false;
	}

	struct ip *iph = get_iph(packet);
	struct tcphdr *tcph = get_tcph(packet);
	
	printf("%-18s", inet_ntoa(iph->ip_src));
	printf("%-18s", inet_ntoa(iph->ip_dst));
	printf("%-10d", ntohs(tcph->th_sport));
	printf("%-10d", ntohs(tcph->th_dport));
	printf("%-10d", ntohl(tcph->th_seq));
	printf("%-10d", ntohl(tcph->th_ack));
	printf("%-10d", ntohs(tcph->th_win));
	printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	u_char *pkt = (u_char*)packet;
	struct ip *iph = get_iph(pkt);
	struct tcphdr *tcph = get_tcph(pkt);

	string ip = string(inet_ntoa(iph->ip_src));

	// if recieve from 192.168.197.142
	if(iph->ip_p == IPPROTO_TCP && ip == TO_IP){
		print_PKT(pkt);

		long SEQ = ntohl(tcph->th_seq);

		// set tcp header
		//tcph->th_sport = htons(1000);
		//tcph->th_dport = htons(1000);
		tcph->th_seq = htonl(0);
		
		if (SEQ >= 8 && SEQ <= 10) // for duplicate ack experiment
		{
			tcph->th_ack = htonl(9); // always request packet of SEQ == 9
		}
		else
		{
			tcph->th_ack = htonl(++SEQ);
		}
		
		//tcph->th_ack = htonl(++SEQ);
		tcph->th_win = htons(0);
		tcph->th_flags = TH_ACK;

		// set ip header
		inet_aton(IP, &iph->ip_src);
		inet_aton(TO_IP, &iph->ip_dst);

		pcap_sendpacket(outdesc, packet, header->len);

		print_PKT(pkt);
	}
}

// main
int main(int argc, char **argv){
	pcap_t *handle;		// handle captured packets

	// Open the output adapter
	if((outdesc = pcap_open_live(DEV, MAX_PKT_SIZE, 1, 1000, errbuf)) == NULL){
		printf("Error opening adapter: %s\n", errbuf);
		return 1;
	}

	// open capture device
	if((handle = pcap_open_live(DEV, MAX_PKT_SIZE, 1, 1000, errbuf)) == NULL){
		printf("Error opening adapter: %s\n", errbuf);
		return 1;
	}

	// callback function when catch packet
	pcap_loop(handle, 0, got_packet, NULL);

	// cleanup
	pcap_close(handle);

	return 0;
}
