#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#define PCKT_LEN 65536
#define DNS_QUERY_NAME_DEFAULT "google.com"

struct DNS_HEADER
{
	unsigned short id;
	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;
	unsigned char rcode :4;
	unsigned char cd :1;
	unsigned char ad :1;
	unsigned char z :1;
	unsigned char ra :1;
	unsigned short q_count;
	unsigned short ans_count;
	unsigned short auth_count;
	unsigned short add_count;
}
; 

struct query
{
	unsigned char name[14];
	//struct question *question;
};

struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host)
{
	int lock = 0, i;
	strcat((char*)host,".");
	for(i = 0; i <strlen((char*)host); i++)
	{
		if(host[i]=='.')
		{
			*dns++ = i-lock;
			for(;lock<i;lock++)
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++='\0';
}

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum+= *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >>16);
	return (unsigned short)(~sum);
}

int main(int argc, char const *argv[])
{
	if(argc != 5) {
		printf("Error: Invalid parameters!\n");
		printf("Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n",argv[0]);
		exit(1);
	}
	u_int16_t src_port, dst_port;
	u_int32_t src_addr, dst_addr;
	src_addr = inet_addr(argv[1]);
	dst_addr = inet_addr(argv[3]);
	src_port = atoi(argv[2]);
	dst_port = atoi(argv[4]);

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	int sd;
	unsigned char buffer[PCKT_LEN],*qname,*reader,host[100];
	memset(buffer, 0 , PCKT_LEN); 
	memcpy(host, DNS_QUERY_NAME_DEFAULT, strlen(DNS_QUERY_NAME_DEFAULT));
	struct iphdr *ip = (struct iphdr *) buffer;
	struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
	
	struct sockaddr_in sin;
	int one = 1;
	const int *val = &one;

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sd < 0){
		perror("socket() error");
		exit(2);
	}
	printf("OK: a raw socket is created.\n");
	
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) <0){
		perror("setsockopt() error");
		exit(2);
	}
	printf("OK: socket option IP_HDRINCL is set.\n");

	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = dst_addr;

	
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->id = htons(54321);
	ip->ttl = 225;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = src_addr;
	ip->daddr = dst_addr;
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+ sizeof(struct query);
	ip->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+ sizeof(struct query));

	udp->source = htons(src_port);
	udp->dest = htons(dst_port);
	udp->len = htons(sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+sizeof(struct query));

	dns = (struct DNS_HEADER *)(buffer+sizeof(struct iphdr) +sizeof(struct udphdr));

	dns->id = (unsigned short) htons(0x66A4);
	dns->qr = 0;
	dns->opcode = 0;
	dns->aa = 0;
	dns->tc = 0;
	dns->rd = 1;
	dns->ra = 0;
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1);
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
	
	struct query *Query = (struct query*)(buffer+ sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct DNS_HEADER));
	ChangetoDnsNameFormat(Query->name, host);
	qinfo = (struct QUESTION*)&buffer[sizeof(struct iphdr) + sizeof(struct udphdr)+sizeof(struct DNS_HEADER) + sizeof(struct query)];

	qinfo->qtype = htons(1);
	qinfo->qclass = htons(1);
	printf("\nSending Packet...\n");
	

	if(sendto(sd,buffer,ip->tot_len,0,(struct sockaddr *)&sin, sizeof(sin)) <0){
	perror("sendto()");
	exit(3);
}	
	printf("OK: one packet is sent.\n");
	close(sd);
	return 0;
}
