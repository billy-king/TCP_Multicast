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
 *  ________________________________________
 * |                                        |
 * | This is send side version (for Node 1) |
 * |________________________________________|
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

#include <ctime>
#include <pthread.h>
#include <iostream>
#include <iomanip>

#define MAX_PKT_SIZE 1512
#define DEV "eth0"
#define IP "192.168.197.142"
#define TO_IP "192.168.197.150"
#define guardTime 1000000 // 1s guard time for go-back-n ARQ
#define timeoutTime 5000000 // 5s for ack timeout
#define MaxWsize 16 // maximum window size

using namespace std;

// structure for packets in the CWND
struct PKT{
	int len;
	u_char packet[MAX_PKT_SIZE];
	bool isSend;
	//bool isACK;
	//bool isTimeout;
	unsigned int receiveACK; // How many ACKs of this PKT has been received.
};

// libpcap
pcap_t *outdesc; // for send out packet
char errbuf[PCAP_ERRBUF_SIZE]; // error buffer for libpcap

// TCP parameters
vector<struct PKT> CWND;
long SEQ_NUM;
long W_size;
long W_start;
long W_end;

clock_t timeend; // for timeout; timeend = timestart + timeoutTime

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

// delay delaytime us
void delay(int delaytime)
{
	clock_t timestop = clock() + delaytime;
	while(clock() < timestop){}
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
		printf("%-10s", "Win Start");
		printf("%-10s", "Win End");
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
	//printf("%-10d", ntohs(tcph->th_win));
	cout << left << setw(10) << W_size;
	cout << left << setw(10) << W_start;
	cout << left << setw(10) << W_end;
	printf("\n");
}

vector<struct PKT> reset_PKT_hdr(vector<struct PKT> pkts){

	for(int i = 0;i < pkts.size();i++){
		struct PKT *pkt = &pkts[i];
		u_char *packet = pkt->packet;
		struct ip *iph = get_iph(packet);
		struct tcphdr *tcph = get_tcph(packet);

		// set tcp header
		tcph->th_sport = htons(0);
		tcph->th_dport = htons(0);
		tcph->th_seq = htonl(0);
		tcph->th_ack = htonl(0);
		tcph->th_win = htons(0);
		tcph->th_flags = 0;

		// set ip header
		inet_aton("0.0.0.0", &iph->ip_src);
		inet_aton("0.0.0.0", &iph->ip_dst);

		pkts[i].isSend = false;
		//pkts[i].isACK = false;
		//pkts[i].isTimeout = false;
		pkts[i].receiveACK = 0;
	}

	return pkts;
}

vector<struct PKT> get_TCP_PKT(pcap_t *indesc){
	struct pcap_pkthdr *pktheader;
	const u_char *pktdata;
	vector<struct PKT> pkts;

	pkts.empty();
	while(pcap_next_ex(indesc, &pktheader, &pktdata) == 1){
		struct PKT pkt;

		if(pktheader->len > MAX_PKT_SIZE) continue;

		pkt.len = pktheader->len;		
		memcpy(pkt.packet, pktdata, pktheader->len);

		// copy 5000 packets
		for(int i = 0;i < 5000;i++){
			pkts.push_back(pkt);
		}

		break;
	}

	return reset_PKT_hdr(pkts);
}

void init_TCP(){
	SEQ_NUM = 1;
	W_size = 1;
	W_start = 1; // consistent with Seq Num
	W_end = ((W_start + W_size - 1) <= CWND.size()) ? (W_start + W_size - 1) : CWND.size();	
}

void *send_out(void *arg){
/*
	for(int i = W_start;i < W_end;i++){ //i<=W_end is better?
		struct PKT *pkt = &CWND[i];
		u_char *packet = pkt->packet;
		struct ip *iph = get_iph(packet);
		struct tcphdr *tcph = get_tcph(packet);

		// set tcp header
		tcph->th_sport = htons(1000);
		tcph->th_dport = htons(1000);
		tcph->th_seq = htonl(SEQ_NUM++);
		tcph->th_ack = htonl(0);
		tcph->th_win = htons(W_size);
		tcph->th_flags = 0;

		// set ip header
		inet_aton(IP, &iph->ip_src);
		inet_aton(TO_IP, &iph->ip_dst);

		pcap_sendpacket(outdesc, packet, pkt->len);
		CWND[i].isSend = true;

		print_PKT(packet);
	}
*/
	int i = W_start;
	while (true)
	{		
		if (i >= W_start && i <= W_end)
		{
			struct PKT *pkt = &CWND[i];
			u_char *packet = pkt->packet;
			struct ip *iph = get_iph(packet);
			struct tcphdr *tcph = get_tcph(packet);

			// set tcp header
			tcph->th_sport = htons(1000);
			tcph->th_dport = htons(1000);
			tcph->th_seq = htonl(i);
			tcph->th_ack = htonl(0);
			tcph->th_win = htons(W_size);
			tcph->th_flags = 0;

			// set ip header
			inet_aton(IP, &iph->ip_src);
			inet_aton(TO_IP, &iph->ip_dst);

			pcap_sendpacket(outdesc, packet, pkt->len);

			if (i == W_start && CWND[i].isSend == false) // the first time sending out the first packet
			{
				CWND[i].isSend = true;
				timeend = clock() + timeoutTime;
			}

			print_PKT(packet);			

			//delay(1000000);// delay 1s for experiment
		}

		i++;

		if (i > W_end) // the latest packet number = W_end
		{
			delay(guardTime);
			i = W_start;
			if ( clock() > timeend && CWND[i].isSend) //timeout
			{
				CWND[i].isSend = true;
				W_size = 1;
				W_end = ((W_start + W_size - 1) <= CWND.size()) ? (W_start + W_size - 1) : CWND.size();
			}
		}
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	u_char *packettemp = (u_char*)packet;
	struct ip *iph = get_iph(packettemp);
	struct tcphdr *tcph = get_tcph(packettemp);

	string ip = string(inet_ntoa(iph->ip_src));
	
/*
	// if recieve from 192.168.197.150
	if(iph->ip_p == IPPROTO_TCP && ip == TO_IP){
		print_PKT(pkt);

		// if is ack
		if(tcph->th_flags & TH_ACK){
			long ACK = ntohl(tcph->th_ack);

			// find ack for which
			for(int i = 0;i < CWND.size();i++){
				struct PKT *CW_PKT = &CWND[i];
				u_char *CW_data = CW_PKT->packet;
				struct tcphdr *CW_tcph = get_tcph(CW_data);

				if(ntohl(tcph->th_ack) == ntohl(CW_tcph->th_seq)){
					CW_PKT->isACK = true;
					break;
				}
			}

			
			bool isAllACK = true;
			for(int i = W_start;i < W_end;i++){
				struct PKT CW_PKT = CWND[i];
				if(CW_PKT.isACK == false){
					isAllACK = false;
					break;
				}
			}			

			if(isAllACK == true){
				W_start = W_start + W_size;
				W_size *= 2;
				W_end = ((W_start + W_size) <= CWND.size()) ? (W_start + W_size) : CWND.size();
				//send_out();
			}
			
		}
	}*/


	// if recieve from 192.168.197.150
	if(iph->ip_p == IPPROTO_TCP && ip == TO_IP){
		print_PKT(packettemp);
		// if is ack
		if(tcph->th_flags & TH_ACK)
		{
			long ACK = ntohl(tcph->th_ack);
			ACK--;
			struct PKT *pkt = &CWND[ACK];
						
			if ( (pkt->receiveACK++) == 0 )
			{	
				if ( ACK == W_start )
				{
					W_start = ACK + 1;					
					W_size = ((2 * W_size) <= MaxWsize) ? (2 * W_size) : MaxWsize;
					W_end = ((W_start + W_size - 1) <= CWND.size()) ? (W_start + W_size - 1) : CWND.size();
				}
			}
			else if (pkt->receiveACK >= 3)
			{
				cout << "Half CWND" << endl;
				cout << "packet number " << ACK << " receiveACK " << pkt->receiveACK << endl;
				pkt->receiveACK = 0;
				W_size = ((W_size / 2) <= 1) ? 1 : (W_size / 2);
				//W_size /= 2;
				W_end = ((W_start + W_size - 1) <= CWND.size()) ? (W_start + W_size - 1) : CWND.size();
			}			
		}		
	//to do: drop the same ack;
	}	
}

// main
int main(int argc, char **argv){
	pcap_t *indesc;		// read .pcap file
	pcap_t *handle;		// handle captured packets
	char *pcap_file = argv[1];		// .pcap file path

	if(argc != 2){
		printf("Must input 2 parameters!\n");
	}

	// Open the output adapter
	if((outdesc = pcap_open_live(DEV, MAX_PKT_SIZE, 1, 1000, errbuf)) == NULL){
		printf("Error opening adapter: %s\n", errbuf);
		return 1;
	}

	// Open the capture
	if((indesc = pcap_open_offline(pcap_file, errbuf)) == NULL){
		printf("Error opening the input file: %s\n", errbuf);
		return 1;
	}

	// get TCP packets
	CWND = get_TCP_PKT(indesc);	
	init_TCP();
	pthread_t thread_send;	
	if ( pthread_create(&thread_send, NULL, &send_out, NULL) )
	{
		cout << "Fail to create send thread.\n";
	}
	else
	{
		cout << "Send thread creation success.\n";
	}			

	/*for(int i = 0;i < CWND.size();i++)
		print_PKT(CWND[i].packet);*/

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













