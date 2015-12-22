/****************************
TCP.cpp
*****************************/

#include <iostream>
#include <string.h>
#include <fstream>
#include <string>
#include <vector>
#include <math.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define MAX_PKT_SIZE 1500
#define MAX_PAYLOAD_SIZE 1460

using namespace std;

typedef unsigned short u16;
u16 checksum(u16* headerData, int len){
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = headerData;
	register int nleft = len;

	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}


	sum = (sum >> 16) + (sum & 0xFFFF);

	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

string ReadFile(string file_path){
	ifstream file(file_path.c_str());
  	string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
	
	return content;
}

int main(int argc, char **argv){
	vector<char> CWND;	/* TCP congestion window */
	string file_path;
	string fContent;
	int file_size;
	int num_Of_pkt;

	pcap_t *outdesc;
	char error[PCAP_ERRBUF_SIZE];
	const char* dev = "eth0";

	struct tcphdr *tcph;
	struct iphdr *iph;

	/* Open the output adapter */
    	if((outdesc = pcap_open_live(dev, 65535, 1, 1000, error) ) == NULL){
        	printf("Error opening adapter: %s\n", error);
        	return 1;
    	}

	while(true){
		cout << "Input File: ";
		cin >> file_path;

		/* read file */
		fContent = ReadFile(file_path);
		file_size = fContent.length();
		num_Of_pkt = ceil((double)file_size/(double)MAX_PAYLOAD_SIZE);

		CWND.resize(num_Of_pkt);
		for(int i = 0;i < num_Of_pkt;i++){
			int start = i*MAX_PAYLOAD_SIZE;
			string sp_fContent = fContent.substr(start, MAX_PAYLOAD_SIZE);
			char payload[MAX_PAYLOAD_SIZE];
			strcpy(payload, sp_fContent.c_str());
			const u_char* u_payload = (const u_char*)payload;

			tcph = new tcphdr;
			cout << tcph->th_win << endl;
			//struct in_addr from_addr, to_addr;

			/*iph = (struct iphdr*) (u_payload + sizeof(struct ethhdr));
			inet_aton("192.168.254.1", &from_addr);
			inet_aton("192.168.254.2", &to_addr);
			iph->saddr = from_addr.s_addr;
			iph->daddr = to_addr.s_addr;
			iph->check = checksum((u16*) iph, sizeof(struct iphdr));*/
			//while(true)
			//pcap_sendpacket(outdesc, u_payload, MAX_PKT_SIZE);
			//cout << u_payload << endl;
		}
	}

	

	return 0;
}
