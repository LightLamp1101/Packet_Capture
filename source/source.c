#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	
#include<stdlib.h>				// malloc 함수 구현
#include<string.h>				// strlen 함수 구현

#include<netinet/ip_icmp.h>		// ICMP 헤더에 대한 선언
#include<netinet/udp.h>			// UDP 헤더에 대한 선언
#include<netinet/tcp.h>			// TCP 헤더에 대한 선언
#include<netinet/ip.h>			// IP 헤더에 대한 선언
#include <netinet/ip_icmp.h>	// ICMP 헤더 선언
#include<netinet/if_ether.h>	// Ethernet 헤더에 대한 선언
#include<net/ethernet.h>		// Ethernet 헤더에 대한 선언
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

void ProcessPacket(unsigned char*, int, int, char inser[]);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);

void PrintData(unsigned char*, int);

void tcp_packet(unsigned char* Buffer, int Size);
void print_ip_header(unsigned char* Buffer, int Size);
void udp_packet(unsigned char* Buffer, int Size);

FILE* logfile;
struct sockaddr_in source, dest;
int tcp = 0, udp = 0, others = 0, igmp = 0, total = 0, i, j;

int main()
{
	int saddr_size, data_size;
	struct sockaddr saddr;
	int num;
	unsigned char* buffer = (unsigned char*)malloc(65536); // 큰 데이터 처리
	unsigned char inser[16];

	while (1) {
		printf("1. HTTP  2. DNS  3. ICMP\n");
		printf("Select : ");
		scanf("%d", &num);

		printf("Insert IP\n");
		scanf("%s", inser);

		if (num <= 3 && num > 0)
			break;
		printf("Select 1~3!\n");

	}

	printf("Ready\n");

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	// setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );

	// 에러 메시지 출력
	if (sock_raw < 0)
	{
		perror("Socket Error");
		return 1;
	}

	// 패킷 받기
	while (1)
	{
		saddr_size = sizeof saddr;

		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)& saddr_size);
		if (data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}

		// 패킷 처리
		tcp_packet(buffer, data_size);
		udp_packet(buffer, data_size);
		ProcessPacket(buffer, data_size, num, inser);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}


void ProcessPacket(unsigned char* buffer, int size, int num, char inser[])
{
	// 이 패킷의 IP 부분 가져오기 (이더넷 헤더 제외)
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	struct tcphdr* tcph;
	struct udphdr* udph;
	int header_size = 0;
	unsigned short iphdrlen = iph->ihl * 4;
	unsigned int protocol = iph->protocol;

	if (protocol == 6) {
		tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
		header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	}
	else if (protocol == 17) {
		udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	}

	char      sos_ip_addr[16];
	char      ded_ip_addr[16];
	char sib[16];
	char dnss[16];
	char icmpp[16];

	strncpy(ded_ip_addr, inet_ntoa(dest.sin_addr), 16);
	strncpy(sos_ip_addr, inet_ntoa(source.sin_addr), 16);
	strncpy(sib, inser, 16);
	strncpy(dnss, inser, 16);
	strncpy(icmpp, inser, 16);

	switch (num) {
	case 1:
		// HTTP 필터링
		if (strcmp(ded_ip_addr, sib) == 0 || strcmp(sos_ip_addr, sib) == 0)
			print_tcp_packet(buffer, size);
		break;

	case 2:
		// DNS 필터링
		if (protocol == 6) {
			if (strcmp(ded_ip_addr, dnss) == 0 || strcmp(sos_ip_addr, dnss) == 0)
				print_tcp_packet(buffer, size);
		}
		else if (protocol == 17) {
			if (strcmp(ded_ip_addr, dnss) == 0 || strcmp(sos_ip_addr, dnss) == 0)
				print_udp_packet(buffer, size);
		}
		break;

	case 3:
		// ICMP 필터링
		if (protocol == 1) {
			//if (strcmp(ded_ip_addr, icmpp) == 0 || strcmp(sos_ip_addr, icmpp) == 0)
				print_icmp_packet(buffer, size);
		}
		break;


	}
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("**IP Header\n");
	printf("   |*IP Version        : %d\n", (unsigned int)iph->version);
	printf("   |*IP Header Length  : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	printf("   |*IP Total Length   : %d  Bytes\n", ntohs(iph->tot_len));
	printf("   |*Protocol : %d\n", (unsigned int)iph->protocol);
	printf("   |*Source IP Address       : %s\n", inet_ntoa(source.sin_addr));
	printf("   |*Destination IP Address   : %s\n", inet_ntoa(dest.sin_addr));
}

void ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	int etherlen = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	printf("\n\n----------------------------------------------\n");

	printf("TCP Packet------------------------------------\n");
	printf("----------------------------------------------\n");
	print_ip_header(Buffer, Size);
	printf("**TCP Header\n");
	printf("   |*Source Port      : %u\n", ntohs(tcph->source));
	printf("   |*Destination Port : %u\n", ntohs(tcph->dest));
	printf("   |*Sequence Number    : %02X\n", ntohl(tcph->seq));
	printf("   |*Acknowledge Number : %02x\n", ntohl(tcph->ack_seq));
	printf("   |*Header Length      : %d BYTES\n", (unsigned int)tcph->doff * 4);
	printf("\n");
	printf("**Payload");
	printf("\n");

	// printf("Ethernet Header\n");
	PrintData(Buffer, etherlen);

	// printf("IP Header\n");
	PrintData(Buffer + etherlen, iphdrlen);

	// printf("TCP Header\n");
	PrintData(Buffer + iphdrlen + etherlen, tcph->doff * 4);

	// printf("Data Payload\n");    
	PrintData(Buffer + header_size, Size - header_size);
}


void tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	ip_header(Buffer, Size);
}

void print_udp_packet(unsigned char* Buffer, int Size)
{

	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	printf("\n\n----------------------------------------------\n");
	printf("UDP Packet------------------------------------\n");
	printf("----------------------------------------------\n");
	print_ip_header(Buffer, Size);

	printf("\n**UDP Header\n");
	printf("   |*Source Port      : %d\n", ntohs(udph->source));
	printf("   |*Destination Port : %d\n", ntohs(udph->dest));
	printf("   |*UDP Length       : %d\n", ntohs(udph->len));

	printf("**Payload");

	printf("IP Header\n");
	PrintData(Buffer, iphdrlen);

	printf("UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof udph);

	printf("Data Payload\n");

	// 전방에 포인터 이동, 문자열 크기 감소
	PrintData(Buffer + header_size, Size - header_size);
}

void udp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	ip_header(Buffer, Size);
}

void print_icmp_packet(unsigned char* Buffer, int Size) {
	unsigned short iphdrlen;
	struct iphdr* iph;
	struct icmphdr* icmph;

	iph = (struct iphdr*)Buffer;
	iphdrlen = iph->ihl * 4;
	icmph = (struct icmphdr*)(Buffer + iphdrlen);


	printf("\n\n----------------------------------------------\n");
	printf("ICMP Packet------------------------------------\n");
	printf("----------------------------------------------\n");
	print_ip_header(Buffer, Size);

	printf("\n**ICMP Header\n");
	printf("   |*Type      : %d\n", (unsigned int)(icmph->type));
	if ((unsigned int)(icmph->type) == 11)
		printf("  (TTL Expired)\n");
	else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
		printf("  (ICMP Echo Reply)\n");

	printf("   |*Code		 : %d\n", (unsigned int)(icmph->code));
	printf("   |*Checksum       : %d\n", ntohs(icmph->checksum));


	printf("**Payload");

	printf("IP Header\n");
	PrintData(Buffer, iphdrlen);

	printf("UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(icmph));

	printf("Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(icmph), (Size - sizeof(icmph) - iph->ihl * 4));

}

void PrintData(unsigned char* data, int Size)
{
	int i, j;
	for (i = 0; i < Size; i++)
	{
		// 16진수 인쇄가 완료된 경우
		if (i != 0 && i % 16 == 0)
		{
			printf("         ");
			for (j = i - 16; j < i; j++)
			{
				// 숫자 또는 알파벳인 경우
				if (data[j] >= 32 && data[j] <= 128)
					printf("%c", (unsigned char)data[j]);

				// 아니면 점 인쇄
				else printf(".");
			}
			printf("\n");
		}

		if (i % 16 == 0) printf("   ");
		printf(" %02X", (unsigned int)data[i]);

		// 마지막 공간 인쇄
		if (i == Size - 1)
		{
			// 공간 추출
			for (j = 0; j < 15 - i % 16; j++)
			{
				printf("   ");
			}

			printf("         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 33 && data[j] <= 127)
				{
					printf("%c", (unsigned char)data[j]);
				}
				else
				{
					printf(".");
				}
			}

			printf("\n");
		}
	}
}