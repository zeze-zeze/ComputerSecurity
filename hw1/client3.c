/*
    An example of using raw sockets.
    You can capture packets by tcpdump:
        tcpdump -X -s0 -i eth0 -p udp
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define PCKT_LEN 16384
#define DNS_QUERY_NAME_DEFAULT "google.com"

unsigned short csum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

//DNS header structure
struct dnshdr
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct Query
{
    char name[10];
    unsigned short int qtype;
    unsigned short int qclass;
};

struct Question
{
    unsigned short int qtype;
    unsigned short int qclass;
};


int main(int argc, char const *argv[])
{
  if (argc != 5) {
    printf("Error: Invalid parameters!\n");
    printf("Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
    exit(1);
  }
  
  u_int16_t src_port, dst_port;
  u_int32_t src_addr, dst_addr;
  src_addr = inet_addr(argv[1]);
  dst_addr = inet_addr(argv[3]);
  src_port = atoi(argv[2]);
  dst_port = atoi(argv[4]);

  int sd;
  char buffer[PCKT_LEN];
  struct iphdr *ip = (struct iphdr *) buffer;
  struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
	struct dnshdr *dns = (struct dnshdr *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
	struct Query *query = (struct Query *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
	//struct Question *question = (struct Question *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + sizeof(struct Query));

  struct sockaddr_in sin;
  int one = 1;
  const int *val = &one;

  memset(buffer, 0, PCKT_LEN);

  // create a raw socket with UDP protocol
  sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sd < 0) {
    perror("socket() error");
    exit(2);
  }
  printf("OK: a raw socket is created.\n");

  // inform the kernel do not fill up the packet structure, we will build our own
  if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    perror("setsockopt() error");
    exit(2);
  }
  printf("OK: socket option IP_HDRINCL is set.\n");

  sin.sin_family = AF_INET;
  sin.sin_port = htons(dst_port);
  sin.sin_addr.s_addr = dst_addr;

  // fabricate the IP header
  ip->ihl      = 5;
  ip->version  = 4;
  ip->tos      = 16; // low delay
  ip->tot_len  = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + sizeof(struct Query);
  ip->id       = htons(54321);
  ip->ttl      = 64; // hops
  ip->protocol = 17; // UDP
  // source IP address, can use spoofed address here
  ip->saddr = src_addr;
  ip->daddr = dst_addr;

  // fabricate the UDP header
  udp->source = htons(src_port);
  // destination port number
  udp->dest = htons(dst_port);
  udp->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr) + sizeof(struct Query));

	// dns query
	dns->id = (unsigned short) htons(getpid());
  dns->qr = 0; //This is a query
  dns->opcode = 0; //This is a standard query
  dns->aa = 0; //Not Authoritative
  dns->tc = 0; //This message is not truncated
  dns->rd = 1; //Recursion Desired
  dns->ra = 0; //Recursion not available! hey we dont have it (lol)
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1); //we have only 1 question
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = 0;

	// point to the query portion
  // filed the data
  // DNS_QUERY_NAME_DEFAULT in here is "github.com"
  memcpy(query->name, DNS_QUERY_NAME_DEFAULT, strlen(DNS_QUERY_NAME_DEFAULT));

  query->qtype = htons(1); //type of the query , A , MX , CNAME , NS etc
  query->qclass = htons(1);                     //its internet (lol)


  // calculate the checksum for integrity
  ip->check = csum((unsigned short *)buffer,
                   sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + sizeof(struct dnshdr) + sizeof(struct Query));
	printf("%d", sizeof(struct udphdr));

  if (sendto(sd, buffer, ip->tot_len, 0,
             (struct sockaddr *)&sin, sizeof(sin)) < 0)
  {
    perror("sendto()");
    exit(3);
  }
  printf("OK: one packet is sent.\n");

  close(sd);
  return 0;
}
