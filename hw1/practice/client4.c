#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
# define DNS_QUERY_NAME_DEFAULT "github.com"

typedef struct query
{
    //           0123456789
    // test name github.com
    char name[10];
    struct question *question;
} Query, *pQuery;

typedef struct question
{
    unsigned short int qtype;
    unsigned short int qclass;
} Question, *pQuestion;

// DNS header structure
typedef struct dns_header
{
    unsigned short int id; // identification number

    // flag
    // unsigned short int == uint16_t
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned short int qr : 1;
    unsigned short int opcode : 4;
    unsigned short int aa : 1;
    unsigned short int tc : 1;
    unsigned short int rd : 1;
    unsigned short int ra : 1;
    unsigned short int z : 3;
    unsigned short int rcode : 4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short int rd : 1;
    unsigned short int tc : 1;
    unsigned short int aa : 1;
    unsigned short int opcode : 4;
    unsigned short int qr : 1;
    unsigned short int rcode : 4;
    unsigned short int z : 3;
    unsigned short int ra : 1;
#endif

    unsigned short qcount;  // question count
    unsigned short ancount; // answer record count
    unsigned short nscount; // name server count
    unsigned short adcount; // additional record count

} DNSHeader, *pDNSHeader;


static int SendDNS(const pDNSStruct ds, const int debug_level)
{
    // Perform a DNS query by sending a packet

    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0)
    {
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    // dst
    sin.sin_port = htons((int)ds->src_port); // set the destination address
    sin.sin_addr.s_addr = inet_addr(ds->src_ip); // set the port

    char *datagram;
    //char *data;
    size_t pksize = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader) + sizeof(Query);
    datagram = (char *)malloc(pksize);

    struct ip *iph;
    iph = (struct ip *)datagram;

    struct udphdr *udph;
    memset(datagram, 0, pksize);
    // filed the data

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        //exit(0);
        return 1;
    }
    // entete ip
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = pksize;
    iph->ip_ttl = 255;
    iph->ip_off = 0;
    iph->ip_id = sizeof(45);
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr("172.18.104.216");
    iph->ip_dst.s_addr = inet_addr("140.113.1.1");

    udph = (struct udphdr *)(datagram + sizeof(struct ip));
    // entete udp
    udph->uh_sport = htons(7);
    udph->uh_dport = htons(53);
    udph->uh_ulen = htons(sizeof(struct udphdr));
    // use the UDP to send the data
    pDNSHeader dnsh = (pDNSHeader)(datagram + sizeof(struct ip) + sizeof(struct udphdr));
    // set the DNS structure to standard queries
    dnsh->id = (unsigned short)htons(getpid());
    dnsh->qr = 0;     // this is a query
    dnsh->opcode = 0; // this is a standard query
    dnsh->aa = 0;     // not authoritative
    dnsh->tc = 0;     // this message is not truncated
    dnsh->rd = 1;     // recursion desired
    dnsh->ra = 0;     // recursion not available! hey we dont have it (lol)
    dnsh->z = 0;
    dnsh->rcode = 0;

    dnsh->qcount = htons(1); //we have only 1 question
    dnsh->ancount = 0;
    dnsh->nscount = 0;
    dnsh->adcount = 0;

    // point to the query portion
    // filed the data
    pQuery query = (pQuery)(datagram + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader));
    // DNS_QUERY_NAME_DEFAULT in here is "github.com"
    memcpy(query->name, DNS_QUERY_NAME_DEFAULT, strlen(DNS_QUERY_NAME_DEFAULT));

    pQuestion question = (pQuestion)(datagram + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader) + sizeof(Query));
    question->qtype = htons(1); //type of the query , A , MX , CNAME , NS etc
    question->qclass = htons(1);                     //its internet (lol)

    if (sendto(socket_fd, datagram, pksize, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        return 1;
    }

    free(datagram);
    close(socket_fd);
    return 0;
}
