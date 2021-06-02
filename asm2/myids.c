/*
 * sniffer.cc
 * - Use the libpcap library to write a sniffer.
 *   By Patrick P. C. Lee.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>                                             
#include <pcap.h>                                             
#include <unistd.h>                                           
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header

#define ETH_HDR_LEN 14
unsigned short in_cksum(unsigned short *, int);
unsigned short ip_checksum(unsigned char *);

unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	unsigned short *w = addr;
	int sum = 0;
	unsigned short answer = 0;
	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if(nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (unsigned short)answer;
}
unsigned short ip_checksum(unsigned char *iphdr)
{
	char buf[20];	// IP header size
	struct ip *iph;
	memcpy(buf, iphdr, sizeof(buf));
	iph = (struct ip *) buf;
	iph->ip_sum = 0;

	return in_cksum((unsigned short *)buf, sizeof(buf));
}

/***************************************************************************
 * Main program
 ***************************************************************************/
int main(int argc, char** argv) {
	pcap_t* pcap;
	char errbuf[256];
	struct pcap_pkthdr hdr;
	const u_char* pkt;					// raw packet
	double pkt_ts;						// raw packet timestamp

	struct ether_header* eth_hdr = NULL;
	struct ip* ip_hdr = NULL;
	struct tcphdr* tcp_hdr = NULL;
	struct udphdr* udp_hdr = NULL;
	
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned int ip_leng = 0;
	unsigned short src_port;
	unsigned short dst_port;
	
	//requirement
	int hh_thresh;
	int h_pscan_thresh;
	int v_pscan_thresh;
	int epoch;
	
	//save information
	//double time = 0;
	int tot_packets = 0;
	int tot_ip_packets = 0;
	int tot_valid_ip_packets = 0;
	int tot_ip_payload_size = 0;
	int first_packet = 0; //when first packet arrives, changes to 1
	time_t start_time;
	time_t now_time;

	int *sip,*size;
	int heavyCounter = 0;

	int Hportcount = 0;
	int horizonalCounter = 0;
	int Hcount = 0;

	int Vip4count = 0;
	int Vcount = 0;
	int verticalCounter = 0;
	
	int tot_tcp_packets = 0;
	int tot_udp_packets = 0;
	int tot_icmp_packets = 0;	
	
	
	//heavy
	int siplength = 0;
	int sipmax = 20;
	//horizontal
	int *hip1,*hip2,*hip3, *hip4,*hport;
	int hiplength = 0;
	int hipmax = 20;
	//vertical
	int *vip1,*vip2,*vip3, *vip4,*vport;
	int viplength = 0;
	int vipmax = 20;
	hip1 = (int*)calloc(20,sizeof(int));
	hip2 = (int*)calloc(20,sizeof(int));	
	hip3 = (int*)calloc(20,sizeof(int));	
	hip4 = (int*)calloc(20,sizeof(int));	
	vip1 = (int*)calloc(20,sizeof(int));	
	vip2 = (int*)calloc(20,sizeof(int));	
	vip3 = (int*)calloc(20,sizeof(int));	
	vip4 = (int*)calloc(20,sizeof(int));	
	hport = (int*)calloc(20,sizeof(int));
	vport = (int*)calloc(20,sizeof(int));
	sip = (int*)calloc(20,sizeof(int));
	size = (int*)calloc(20,sizeof(int));
	int mode;
	
	if (argc != 7) {
		fprintf(stderr, "Usage: %s <online/offine> <interface> <hh_thresh> <h_pscan_thresh> <v_pscan_thresh>\n", argv[0]);
		exit(-1);
	}
	hh_thresh = atoi(argv[3]);
	hh_thresh = hh_thresh*1024;
	h_pscan_thresh = atoi(argv[4]);
	v_pscan_thresh = atoi(argv[5]);
	epoch = atoi(argv[6]) ;
	printf("hev: %d KB : %d vert : %d epoch : %d\n",hh_thresh/(1024), h_pscan_thresh ,  v_pscan_thresh, epoch );		
	
	if (strcmp (argv[1], "online") == 0)
	{
		mode = 1;
		if ((pcap = pcap_open_live(argv[2], 1500, 1, 1000, errbuf)) == NULL) {
			fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[2], errbuf);
			exit(-1);
		}
	}

	if (strcmp (argv[1], "offline") == 0)
	{
		mode = 0;
		if ((pcap = pcap_open_offline(argv[2], errbuf)) == NULL) {
		fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
		exit(-1);
		}
	}
	
	// open input pcap file                                         
	//if ((pcap = pcap_open_live(argv[2], 1500, 1, 1000, errbuf)) == NULL) {
	//	fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
	//	exit(-1);
	//}
	///printf("HIHIHI!");
	while (1) {
		// get the timestamp
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec;
			if (first_packet == 0){
				first_packet = 1; //first packet aririves
				if (mode == 1){
					//online mode time
					start_time = time(NULL);
				} else {
					//offline mode time
					start_time = (int)pkt_ts;
				}
				
			}
			if (mode == 1){
				now_time = time(NULL);
			} else {
				now_time = (int)pkt_ts;
			}
			
			//printf("Now: %d, start: %d\n", (int)now_time, (int)start_time);
			
			//printf("%f\n", pkt_ts);
			//printf("%lf:" ,pkt_ts);
			if (now_time - start_time >= epoch){
				printf("Total number of observed packets: %d\n", tot_packets);
				printf("Total number of observed IP packets: %d\n", tot_ip_packets);
				printf("Total number of observed valid IP packets: %d\n", tot_valid_ip_packets);
				printf("Total IP payload size: %d bytes\n", tot_ip_payload_size);
				printf("Total number of TCP packets: %d\n", tot_tcp_packets);
				printf("Total number of UDP packets: %d\n", tot_udp_packets);
				printf("Total number of ICMP packets: %d\n", tot_icmp_packets);
				//printf("time now: %lf \n",(pkt_ts - time));
				//printf("Total number of ip: %d \n",hiplength);
				//time = 0;
				first_packet = 0; //reset
			}
			if (first_packet == 0)
			{
				if (mode == 1){
					//online reset
					start_time = time(NULL);
				} else {
					//offline reset
					start_time = (int)pkt_ts;

				}
				ip_leng = 0;
				tot_packets = 0;
				tot_ip_packets = 0;
				tot_valid_ip_packets = 0;
				tot_ip_payload_size = 0;	
				heavyCounter = 0;
				horizonalCounter = 0;
				verticalCounter = 0;
				tot_tcp_packets = 0;
				tot_udp_packets = 0;
				tot_icmp_packets = 0;
				hiplength = 0;	
				viplength = 0;
				siplength = 0;
				//free(hip1);free(hip2);free(hip3);free(hip4);free(hport);free(hportlength);
				//free(vip1);free(vip2);free(vip3);free(vip4);free(vport);free(vip4length);
			}
		if ((pkt = pcap_next(pcap, &hdr)) != NULL) {
			// parse the headers
			
			eth_hdr = (struct ether_header*)pkt;
			switch (ntohs(eth_hdr->ether_type)) {
				case ETH_P_IP:		// IP packets (no VLAN header)
					ip_hdr = (struct ip*)(pkt + ETH_HDR_LEN); 
					break;
				case 0x8100:		// with VLAN header (with 4 bytes)
					ip_hdr = (struct ip*)(pkt + ETH_HDR_LEN + 4); 
					break;
			}
			tot_packets = tot_packets + 1;
			// if IP header is NULL (not IP or VLAN), continue. 
			if (ip_hdr == NULL) {
				continue;
			}else{
				tot_ip_packets = tot_ip_packets + 1;
			}
			
			// add one total packet
			
			/*if (ip_hdr->ip_p == 1 || ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17)
			{
				tot_ip_packets = tot_ip_packets + 1;
			}*/
			// IP addresses are in network-byte order	
			src_ip = ip_hdr->ip_src.s_addr;

			// payload size
			ip_leng = ntohs(ip_hdr -> ip_len) - (ip_hdr -> ip_hl)*4;

			//printf ("\n\n%d\n\n",ip_leng);
			
			dst_ip = ip_hdr->ip_dst.s_addr;
			//checksum
			//printf("ip_hdr->ip_sum = %x\t IP checksum =%x\n",ip_hdr->ip_sum, ip_checksum((char*)ip_hdr) );
			if(ip_hdr->ip_sum != ip_checksum((char*)ip_hdr)){
				printf("IP checksum error (%x,%x)\n", ip_hdr->ip_sum, ip_checksum((char*)ip_hdr));
				continue;
				
			}else{
				tot_valid_ip_packets = tot_valid_ip_packets + 1;
				//printf("Now tot_valid_ip_packets %d\n", tot_valid_ip_packets);
			}
			
			if (ip_hdr->ip_p == IPPROTO_TCP) {
				tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + 
						(ip_hdr->ip_hl << 2)); 
				src_port = ntohs(tcp_hdr->source);
				dst_port = ntohs(tcp_hdr->dest);
				//tot_valid_ip_packets = tot_valid_ip_packets + 1;
				tot_tcp_packets = tot_tcp_packets + 1;
				tot_ip_payload_size = tot_ip_payload_size + ip_leng;	
				Hportcount = 0;	
				Vip4count = 0;
				//printf ("sip : %d", src_ip);
				for (int i = 0; i<=siplength; ++i)
				{
					if(sip[i] == src_ip)
					{
						size[i] = size[i] + ip_leng;
						//printf("TCP i: %d ,src_ip : %d, sizenow: %d\n",i,sip[i], size[i]);
						if (size[i] > hh_thresh && heavyCounter == 0)
						{
							//printf("%d\n ", size[i]);
							printf("At timestamp %lf: A heavy hitter is detected\n""- source IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);heavyCounter++;
						}
						break;
					}

					if (i == siplength)
					{
						//printf("create!\n");
						if(siplength == sipmax)
						{
							//printf("extend!\n");
							sipmax = sipmax + 10;
							sip = realloc(sip, sipmax * sizeof(int));
							size = realloc(size, sipmax * sizeof(int));
						}
						sip[i] = src_ip;
						size[i] = ip_leng;
						siplength++;break;
					}
				}
				for (int i = 0; i<=hiplength; ++i)
				{
					if(hip1[i]==(dst_ip & 0xff) && hip2[i]==(dst_ip >> 8 & 0xff) && hip3[i]== (dst_ip >> 16& 0xff) && hip4[i]==(dst_ip >> 24 & 0xff))
					{
						//printf("Front same!\n");
						if (hport[i] == dst_port)
						{
							//printf("same!\n");
							break;
						}
						else {
							//printf("different!\n");
							Hportcount = Hportcount + 1;
							if (Hportcount > h_pscan_thresh && horizonalCounter == 0){
							//printf("At timestamp %lf: A horizontal portscan is detected\n""- source IP: %d.%d.%d.%d, port: %hu\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_port);
							printf("At timestap %lf: A vertical portscan is dectected\n""- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_ip & 0xff, (dst_ip >> 8) & 0xff,(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);

							horizonalCounter++;
							}
						}
				
					}
					if(i == hiplength)
					{
						//printf("NO same!\n");
						if (hiplength == hipmax)
							{
							hipmax = hipmax + 10;	
							hip1 = realloc(hip1, hipmax * sizeof(int));
							hip2 = realloc(hip2, hipmax * sizeof(int));	
							hip3 = realloc(hip3, hipmax * sizeof(int));	
							hip4 = realloc(hip4, hipmax * sizeof(int));	
							hport = realloc(hport, hipmax * sizeof(int));
				
							}
						hip1[i]=(dst_ip & 0xff); hip2[i]=(dst_ip >> 8 & 0xff);
						hip3[i]= (dst_ip >> 16 & 0xff); hip4[i]=(dst_ip >> 24 & 0xff);
						hport[i] = dst_port;
						hiplength = hiplength + 1;
						break;}	
				
				}
				for (int i = 0; i<=viplength; ++i)
				{


				if(vport[i] == dst_port)
					{
						if (vip1[i]==(dst_ip & 0xff) && vip2[i]==(dst_ip >> 8 & 0xff) && vip3[i]== (dst_ip >> 16 & 0xff) && vip4[i]==(dst_ip >> 24 & 0xff))
						{
							//printf("same!\n");
							break;
						}
						else {
							//printf("different!\n");	
							Vip4count = Vip4count + 1;
							if (Vip4count > v_pscan_thresh && verticalCounter == 0){
							//printf("At timestap %lf: A vertical portscan is dectected\n""- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_ip & 0xff, (dst_ip >> 8) & 0xff,(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);
							printf("At timestamp %lf: A horizontal portscan is detected\n""- source IP: %d.%d.%d.%d, port: %hu\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_port);
							
							verticalCounter++;
							}
						}
				
					}
					if(i == viplength)
					{
						//printf("No same!\n");
						if (viplength == vipmax)
							{
							vipmax = vipmax + 10;		
							vip1 = realloc(vip1, hipmax * sizeof(int));
							vip2 = realloc(vip2, hipmax * sizeof(int));
							vip3 = realloc(vip3, hipmax * sizeof(int));
							vip4 = realloc(vip4, hipmax * sizeof(int));
							vport = realloc(vport, hipmax * sizeof(int));
				
							}
						vip1[i]=(dst_ip & 0xff); vip2[i]=(dst_ip >> 8 & 0xff);
						vip3[i]= (dst_ip >> 16 & 0xff); vip4[i]=(dst_ip >> 24 & 0xff);
						vport[i] = dst_port;
						viplength = viplength + 1;
						break;}	
				
				}
				
							
				
				/*printf("TCP %lf: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", 
						pkt_ts, 
						src_ip & 0xff, (src_ip >> 8) & 0xff, 
						(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff, 
						src_port, 
						dst_ip & 0xff, (dst_ip >> 8) & 0xff, 
						(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff, 
						dst_port);*/
				
			} 
			else if (ip_hdr->ip_p == IPPROTO_UDP)
			{	
				udp_hdr = (struct udphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2)); 
				src_port = ntohs(udp_hdr->source);
				dst_port = ntohs(udp_hdr->dest);
				//tot_valid_ip_packets = tot_valid_ip_packets + 1;
				tot_udp_packets = tot_udp_packets + 1;
				tot_ip_payload_size = tot_ip_payload_size + ip_leng;	
				Hportcount = 0;	
				Vip4count = 0;
				//printf ("HIPlength : %d\n", hiplength);
				/*printf("UDP %lf: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", 
						pkt_ts, 
						src_ip & 0xff, (src_ip >> 8) & 0xff, 
						(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff, 
						src_port, 
						dst_ip & 0xff, (dst_ip >> 8) & 0xff, 
						(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff, 
						dst_port);	*/
				for (int i = 0; i<=siplength; ++i)
				{
					if(sip[i] == src_ip)
					{
						size[i] = size[i] + ip_leng;
						//printf("UDP i: %d ,src_ip : %d, sizenow(KB): %d\n",i,sip[i], size[i]/1024);
						
						if (size[i] > hh_thresh && heavyCounter == 0)
						{
							
							printf("At timestamp %lf: A heavy hitter is detected\n""- source IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);heavyCounter++;
						}
						break;
					}

					if (i == siplength)
					{
						//printf("create!\n");
						if(siplength == sipmax)
						{
							//printf("extend!\n");
							sipmax = sipmax + 10;
							sip = realloc(sip, sipmax * sizeof(int));
							size = realloc(size, sipmax * sizeof(int));
						}
						sip[i] = src_ip;
						size[i] = ip_leng;
						siplength++;break;
					}
				}

				for (int i = 0; i<=hiplength; ++i)
				{
					if(hip1[i]==(dst_ip & 0xff) && hip2[i]==(dst_ip >> 8 & 0xff) && hip3[i]== (dst_ip >> 16 & 0xff) && hip4[i]==(dst_ip >> 24 & 0xff))
					{
						if (hport[i] == dst_port)
						{
							//printf("same!");
							break;
						}
						else {
							Hportcount = Hportcount + 1;
							if (Hportcount > h_pscan_thresh && horizonalCounter == 0){
							//printf("At timestamp %lf: A horizontal portscan is detected\n""- source IP: %d.%d.%d.%d, port: %hu\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_port);
							printf("At timestap %lf: A vertical portscan is dectected\n""- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_ip & 0xff, (dst_ip >> 8) & 0xff,(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);
							horizonalCounter++;
							}
						}
				
					}
					if(i == hiplength)
					{
						if (hiplength == hipmax)
							{
							hipmax = hipmax + 10;	
							hip1 = realloc(hip1, hipmax * sizeof(int));
							hip2 = realloc(hip2, hipmax * sizeof(int));	
							hip3 = realloc(hip3, hipmax * sizeof(int));	
							hip4 = realloc(hip4, hipmax * sizeof(int));	
							hport = realloc(hport, hipmax * sizeof(int));
				
							}
						hip1[i]=(dst_ip & 0xff); hip2[i]=(dst_ip >> 8 & 0xff);
						hip3[i]= (dst_ip >> 16 & 0xff); hip4[i]=(dst_ip >> 24 & 0xff);
						hport[i] = dst_port;
						hiplength = hiplength + 1;
						break;}	
				
				}
				for (int i = 0; i<=viplength; ++i)
				{
					if(vport[i] == dst_port)
					{
						if (vip1[i]==(dst_ip & 0xff) && vip2[i]==(dst_ip >> 8 & 0xff) && vip3[i]== (dst_ip >> 16 & 0xff) && vip4[i]==(dst_ip >> 24 & 0xff))
						{
							//printf("same!");
							break;
						}
						else {
							//printf("different!");
							Vip4count = Vip4count + 1;
							if (Vip4count > v_pscan_thresh && verticalCounter == 0){
							//printf("At timestap %lf: A vertical portscan is dectected\n""- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_ip & 0xff, (dst_ip >> 8) & 0xff,(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);
							printf("At timestamp %lf: A horizontal portscan is detected\n""- source IP: %d.%d.%d.%d, port: %hu\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,dst_port);
							verticalCounter++;
							}
						}
				
					}
					if(i == viplength)
					{
						if (viplength == vipmax)
							{
							//printf("extend!!!");
							vipmax = vipmax + 10;		
							vip1 = realloc(vip1, hipmax * sizeof(int));
							vip2 = realloc(vip2, hipmax * sizeof(int));
							vip3 = realloc(vip3, hipmax * sizeof(int));
							vip4 = realloc(vip4, hipmax * sizeof(int));
							vport = realloc(vport, hipmax * sizeof(int));
				
							}
						vip1[i]=(dst_ip & 0xff); vip2[i]=(dst_ip >> 8 & 0xff);
						vip3[i]= (dst_ip >> 16 & 0xff); vip4[i]=(dst_ip >> 24 & 0xff);
						vport[i] = dst_port;
						viplength = viplength + 1;
						break;}	
				
				}
				
				//printf("UDP\n");

			}
			else if (ip_hdr->ip_p == IPPROTO_ICMP)
			{	
				//tot_valid_ip_packets = tot_ip_packets + 1;
				tot_icmp_packets = tot_icmp_packets + 1;
				tot_ip_payload_size = tot_ip_payload_size + ip_leng;
				//printf("ICMP");
				for (int i = 0; i<=siplength; ++i)
				{
					if(sip[i] == src_ip)
					{
						size[i] = size[i] + ip_leng;
						//printf("ICMP i: %d ,src_ip : %d, sizenow: %d\n",i,sip[i], size[i]);
						if (size[i] > hh_thresh && heavyCounter == 0)
						{
							
							printf("At timestamp %lf: A heavy hitter is detected\n""- source IP: %d.%d.%d.%d\n",pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);heavyCounter++;
						}
						break;
					}

					if (i == siplength)
					{
						//printf("create!\n");
						if(siplength == sipmax)
						{
							//printf("extend!\n");
							sipmax = sipmax + 10;
							sip = realloc(sip, sipmax * sizeof(int));
							size = realloc(size, sipmax * sizeof(int));
						}
						sip[i] = src_ip;
						size[i] = ip_leng;
						siplength++;break;
					}
				}
			}
			else
			{
			}
			
			
		}
		else
		{
			if (mode == 0) {
				printf("Total number of observed packets: %d\n", tot_packets);
				printf("Total number of observed IP packets: %d\n", tot_ip_packets);
				printf("Total number of observed valid IP packets: %d\n", tot_valid_ip_packets);
				printf("Total IP payload size: %d bytes\n", tot_ip_payload_size);
				printf("Total number of TCP packets: %d\n", tot_tcp_packets);
				printf("Total number of UDP packets: %d\n", tot_udp_packets);
				printf("Total number of ICMP packets: %d\n", tot_icmp_packets);
				//printf("time now: %lf \n",(pkt_ts - time));
				//printf("Total number of ip: %d \n",hiplength);
				//time = 0;
				first_packet = 0; //reset
				break;}
		}
	}
	
	// close files
	pcap_close(pcap);
	
	return 0;
}
