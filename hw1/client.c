#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

/* Opening a raw socket */
sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
if(sock_raw == -1)
printf("error in socket");

/* Getting the index of the interface to send a packet */
struct ifreq ifreq_i;
memset(&ifreq_i,0,sizeof(ifreq_i));
strncpy(ifreq_i.ifr_name,"wlan0",IFNAMSIZ-1); //giving name of Interface
 
if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
printf("error in index ioctl reading");//getting Index Name
 
printf("index=%d\n",ifreq_i.ifr_ifindex);

/* Getting the MAC address of the interface */
struct ifreq ifreq_c;
memset(&ifreq_c,0,sizeof(ifreq_c));
strncpy(ifreq_c.ifr_name,"wlan0",IFNAMSIZ-1);//giving name of Interface
 
if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0) //getting MAC Address
printf("error in SIOCGIFHWADDR ioctl reading");

/* Getting the IP address of the interface */
struct ifreq ifreq_ip;
memset(&ifreq_ip,0,sizeof(ifreq_ip));
strncpy(ifreq_ip.ifr_name,"wlan0",IFNAMSIZ-1);//giving name of Interface
if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0) //getting IP Address
{
    printf("error in SIOCGIFADDR \n");
}

/* Constructing the Ethernet header */
sendbuff=(unsigned char*)malloc(64); // increase in case of more data
memset(sendbuff,0,64);

struct ethhdr *eth = (struct ethhdr *)(sendbuff);
 
eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);
 
// filling destination mac. DESTMAC0 to DESTMAC5 are macro having octets of mac address.
eth->h_dest[0] = DESTMAC0;
eth->h_dest[1] = DESTMAC1;
eth->h_dest[2] = DESTMAC2;
eth->h_dest[3] = DESTMAC3;
eth->h_dest[4] = DESTMAC4;
eth->h_dest[5] = DESTMAC5;
 
eth->h_proto = htons(ETH_P_IP); //means next header will be IP header
 
// end of ethernet header 
total_len+=sizeof(struct ethhdr);

/* Constructing the IP header */
struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(struct ethhdr));
iph->ihl = 5;
iph->version = 4;
iph->tos = 16;
iph->id = htons(10201);
iph->ttl = 64;
iph->protocol = 17;
iph->saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
iph->daddr = inet_addr("destination_ip"); // put destination IP address
 
total_len += sizeof(struct iphdr);

/* Construct the UDP header */
uh->source = htons(23451);
uh->dest = htons(23452);
uh->check = 0;
 
total_len+= sizeof(struct udphdr);

/* Adding data or the UDP payload */
sendbuff[total_len++] = 0xAA;
sendbuff[total_len++] = 0xBB;
sendbuff[total_len++] = 0xCC;
sendbuff[total_len++] = 0xDD;
sendbuff[total_len++] = 0xEE;

/* Filling the remaining fields of the IP and UDP headers */
uh->len = htons((total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)));
//UDP length field
iph->tot_len = htons(total_len - sizeof(struct ethhdr));
//IP length field

/* The IP header checksum */
unsigned short checksum(unsigned short* buff, int _16bitword)
{
unsigned long sum;
for(sum=0;_16bitword>0;_16bitword--)
sum+=htons(*(buff)++);
sum = ((sum >> 16) + (sum & 0xFFFF));
sum += (sum>>16);
return (unsigned short)(~sum);
}
 
iph->check = checksum((unsigned short*)(sendbuff + sizeof(struct ethhdr)), (sizeof(struct iphdr)/2));

/* Sending the packet */
struct sockaddr_ll sadr_ll;
sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
sadr_ll.sll_addr[0] = DESTMAC0;
sadr_ll.sll_addr[1] = DESTMAC1;
sadr_ll.sll_addr[2] = DESTMAC2;
sadr_ll.sll_addr[3] = DESTMAC3;
sadr_ll.sll_addr[4] = DESTMAC4;
sadr_ll.sll_addr[5] = DESTMAC5;

send_len = sendto(sock_raw,sendbuff,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
if(send_len<0)
{
    printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
    return -1; 
}

