#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <if_ether.h>
#include <ip.h>
#include <udp.h>

/* Opening a raw socket */
int sock_r;
sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
if(sock_r<0)
{
    printf("error in socket\n");
    return -1;
}

/* Reception of the network packet */
unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
memset(buffer,0,65536);
struct sockaddr saddr;
int saddr_len = sizeof (saddr);
 
//Receive a network packet and copy in to buffer
buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
if(buflen<0)
{
    printf("error in reading recvfrom function\n");
    return -1;
}

/* Extracting the Ethernet header */
struct ethhdr *eth = (struct ethhdr *)(buffer);
printf("\nEthernet Header\n");
printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
printf("\t|-Protocol : %d\n",eth->h_proto);

/* Extracting the IP header */
unsigned short iphdrlen;
struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
memset(&source, 0, sizeof(source));
source.sin_addr.s_addr = ip->saddr;
memset(&dest, 0, sizeof(dest));
dest.sin_addr.s_addr = ip->daddr;

fprintf(log_txt, "\t|-Version : %d\n",(unsigned int)ip->version);
fprintf(log_txt , "\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
fprintf(log_txt , "\t|-Type Of Service : %d\n",(unsigned int)ip->tos);
fprintf(log_txt , "\t|-Total Length : %d Bytes\n",ntohs(ip->tot_len));
fprintf(log_txt , "\t|-Identification : %d\n",ntohs(ip->id));
fprintf(log_txt , "\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
fprintf(log_txt , "\t|-Protocol : %d\n",(unsigned int)ip->protocol);
fprintf(log_txt , "\t|-Header Checksum : %d\n",ntohs(ip->check));
fprintf(log_txt , "\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
fprintf(log_txt , "\t|-Destination IP : %s\n",inet_ntoa(dest.sin_addr));

/* The transport layer header */
struct iphdr *ip = (struct iphdr *)( buffer + sizeof(struct ethhdr) );
// getting actual size of IP header
iphdrlen = ip->ihl*4;
// getting pointer to udp header
struct tcphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

fprintf(log_txt , "\t|-Source Port : %d\n" , ntohs(udp->source));
fprintf(log_txt , "\t|-Destination Port : %d\n" , ntohs(udp->dest));
fprintf(log_txt , "\t|-UDP Length : %d\n" , ntohs(udp->len));
fprintf(log_txt , "\t|-UDP Checksum : %d\n" , ntohs(udp->check));

/* Extracting data */
unsigned char * data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
 
for(i=0;i<remaining_data;i++)
{
    if(i!=0 && i%16==0)
    fprintf(log_txt,"\n");
    fprintf(log_txt," %.2X ",data[i]);
}
