/*
 * Author: Ritchit Nayak
 * Purpose: A simple ping CLI tool.
 * Language:  C
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>

#include <pthread.h>


#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   2
#define MAX_NO_PACKETS  3

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

int gAddressFamily = AF_INET; // AF_INET6
int gProtocol = IPPROTO_ICMP; // IPPROTO_ICMPV6
int gTtl = 64;

int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;

volatile int stop = 0;

struct sockaddr_in  daddr;
struct sockaddr_in6 daddr6;
struct sockaddr_in faddr;
struct sockaddr_in6 faddr6;
struct sockaddr_in6 self_addr6;

pid_t pid;


void statistics(int signo);
void handler(int signo);
int pack(int pack_no);
void *send_packet(void *p);
void *recv_packet(void *p);
void printRtt(char *buf, int len, struct timeval *tvrecv);
float diff_ms(struct timeval *out, struct timeval *in);
int lookup_host(const char *host);
unsigned short icmp6Checksum(unsigned short *buffer, int icmplen);
int setTtl();

/**
 * Print command options and usage
 *
 * @param progname Name of the command.
 * @return sum of `values`, or 0.0 if `values` is empty.
 */
void usage(char *progname)
{
    printf("usage: %s [options] <host> \n", progname);
    printf("        host        Remote machine to ping\n");
    printf("        options: \n");
    printf("            -a 4|6           Address family \n");
    printf("            -s <IP>          Source ip according to address family\n");
    printf("            -t <TTL value>   TTL value\n");
    return;
}

/**
 * Print ping statistics
 *
 * @param signo signal received.
 */
void statistics(int signo)
{
    printf("\n--------------------PING statistics-------------------\n");
    printf("%d packets transmitted, %d received , %.2f%% lost\n", nsend, nreceived, ((float)(nsend - nreceived)*100) / nsend);
    close(sockfd);
    exit(1);
}


/**
 * Handler to stop sending and receiving threads
 *
 * @param signo signal received.
 */
void handler(int signo)
{
    stop = 1;
}

/**
 * Thread to send packets
 *
 */
void *send_packet(void *p)
{
    int packetsize, sec_no = 1;
    while(!stop)
    {
        packetsize = pack(sec_no);
        if (gAddressFamily == AF_INET)
        {
            if(sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)&daddr, sizeof(daddr)) < 0)
            {
                perror("sendto error");
                continue;
            }
            else
            {
                sec_no++;
                nsend++;
            }
            sleep(1);
        }
        else if(gAddressFamily == AF_INET6)
        {
            if(sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)&daddr6, sizeof(daddr6)) < 0)
            {
                perror("sendto error");
                continue;
            }
            else
            {
                sec_no++;
                nsend++;
            }
            sleep(1);
        }
        else
        {
            stop = 1;
        }
    }
    return(0);
}


/**
 * Thread to receive packets
 *
 */
void *recv_packet(void *p)
{
    struct timeval tvrecv;
    unsigned int rc, fromlen;
    extern int errno;

    signal(SIGALRM, statistics);
    alarm(MAX_WAIT_TIME);

    if (gAddressFamily == AF_INET)
    {
        fromlen = sizeof(faddr);
        while(!stop)
        {
            alarm(MAX_WAIT_TIME);
            rc = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr*) &faddr, &fromlen);
            if ((rc < 0) && (errno == EINTR))
            {
                stop = 1;
                continue;
            }
            gettimeofday(&tvrecv, NULL);
            printRtt(recvpacket, rc, &tvrecv);
        }
    }
    else if(gAddressFamily == AF_INET6)
    {
        fromlen = sizeof(faddr6);
        while(!stop)
        {
            alarm(MAX_WAIT_TIME);
            rc = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr*) &faddr6, &fromlen);
            if ((rc < 0) && (errno == EINTR))
            {
                stop = 1;
                continue;
            }
            gettimeofday(&tvrecv, NULL);
            printRtt(recvpacket, rc, &tvrecv);
        }
    }
    return(0);
}

int main(int argc, char *argv[])
{
    pthread_t s,r;
    char buf[INET6_ADDRSTRLEN];
    struct hostent *host;
    unsigned long inaddr = 0l;
    int waittime = MAX_WAIT_TIME;
    int size = 50 * 1024;
    int count = 5;
    int opt;

    if (argc < 6)
    {
        usage("ping");
        exit(1);
    }

    while((opt = getopt(argc, argv, ":a:s:t:")) != -1)
    {
        switch(opt)
        {
            case 'a':
                if(strcmp("4", optarg) == 0)
                {
                    gAddressFamily = AF_INET;
                    gProtocol = IPPROTO_ICMP;
                }
                else if(strcmp("6", optarg) == 0)
                {
                    gAddressFamily = AF_INET6;
                    gProtocol = IPPROTO_ICMPV6;
                }
                else
                {
                    usage("ping");
                    exit(1);
                }
                break;
            case 's':
                inet_pton(AF_INET6, optarg, &self_addr6.sin6_addr);
                break;
            case 't':
                gTtl = atoi(optarg);
                break;
            case '?':
              printf("unknown option: %c\n", optopt);
              usage("ping");
              break;
        }
    }

    if ((sockfd = socket(gAddressFamily, SOCK_RAW, gProtocol)) < 0)
    {
        perror("socket error");
        exit(1);
    }

    setTtl();

    setuid(getuid());

    bzero(&daddr, sizeof(daddr));
    bzero(&daddr6, sizeof(daddr6));

    daddr.sin_family = gAddressFamily;
    daddr6.sin6_family = gAddressFamily;

    if((inaddr = inet_addr(argv[optind])) == INADDR_NONE)
    {
        printf("domain\n");
        if(lookup_host(argv[optind]) < 0)
        {
            perror("Hostname lookup error");
            exit(1);
        }
    }
    else
    {
        printf("ip\n");
        inet_pton(AF_INET, argv[optind], &daddr.sin_addr);
        inet_pton(AF_INET6, argv[optind], &daddr6.sin6_addr);
    }

    pid = getpid();

    if (gAddressFamily == AF_INET)
    {
        inet_ntop(AF_INET, &(daddr.sin_addr), buf, INET_ADDRSTRLEN);
        printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[optind], buf, datalen);
    }
    else
    {
        inet_ntop(AF_INET6, &(daddr6.sin6_addr), buf, INET6_ADDRSTRLEN);
        printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[optind], buf, datalen);
    }

    signal(SIGINT, handler);
    pthread_create(&s,NULL,send_packet,NULL);
	  pthread_create(&r,NULL,recv_packet,NULL);
    pthread_join(s, NULL);
    pthread_join(r, NULL);
    return(0);
}


/**
 * Calculates difference in timeval in milliseconds
 *
 * @param out timeval of outgoing packet.
 * @param in timeval of incoming packet.
 * @return difference in timeval in milliseconds.
 */
float diff_ms(struct timeval *out, struct timeval *in)
{
    return((float)(((in->tv_sec - out->tv_sec) * 1000000) + (in->tv_usec - out->tv_usec)) / 1000.0);
}


/**
 * Fills in the ICMPv4 header
 *
 * @param buf buffer to fill in the header values.
 * @param datasize size of the ICMP payload.
 * @param seqno sequence number to be filled in header.
 * @return size of the ICMPv4 packet.
 */
int initIcmp4Header(char *buf, int datasize, int seqno)
{
    struct icmp   *icmp_hdr = NULL;
    struct timeval *tval;
    char          *datapart = NULL;

    icmp_hdr                = (struct icmp *)buf;
    icmp_hdr->icmp_type     = ICMP_ECHO;        // request an ICMP echo
    icmp_hdr->icmp_code     = 0;
    icmp_hdr->icmp_id       = pid;
    icmp_hdr->icmp_cksum    = 0;
    icmp_hdr->icmp_seq      = seqno;

    datapart = buf + sizeof(struct icmp);
    memset(datapart, '0', datasize);

    tval = (struct timeval*)icmp_hdr->icmp_data;
    gettimeofday(tval, NULL);
    return(sizeof(struct icmp)+datalen);
}


/**
 * Fills in the ICMPv6 header
 *
 * @param buf buffer to fill in the header values.
 * @param datasize size of the ICMP payload.
 * @param seqno sequence number to be filled in header.
 * @return size of the ICMPv6 packet.
 */
int initIcmp6Header(char *buf, int datasize, int seqno)
{
    struct icmp6_hdr    *icmp6_hdr = NULL;
    struct timeval *tval;
    char                 *datapart = NULL;

    icmp6_hdr                 = (struct icmp6_hdr *)buf;
    icmp6_hdr->icmp6_type     = ICMP6_ECHO_REQUEST;
    icmp6_hdr->icmp6_code     = 0;
    icmp6_hdr->icmp6_cksum    = 0;

    icmp6_hdr->icmp6_dataun.icmp6_un_data16[0] = htons(pid); /* identifier */
    icmp6_hdr->icmp6_dataun.icmp6_un_data16[1] = htons(seqno); /* sequence no */

    datapart = (char *)buf + sizeof(struct icmp6_hdr);
    memset(datapart, '0', datasize);

    tval = (struct timeval*)datapart;
    gettimeofday(tval, NULL);
    return(sizeof(struct icmp6_hdr)+datalen);
}

/**
 * Fills in the ICMPv4 header
 *
 * @param buffer buffer to calculate the checksum of.
 * @param size length of the buffer for which checksum is to be evaluated.
 * @return checksum of the given buffer.
 */
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

/**
 * Wrapper to calculate checksum of both ICMPv4 and ICMPv6
 *
 * @param buffer buffer to calculate the checksum of.
 * @param packetlen length of the buffer for which checksum is to be evaluated.
 */
void ComputeIcmpChecksum(char *buf, int packetlen)
{
    struct icmp *icmpv4 = NULL;
    struct icmp6_hdr *icmpv6 = NULL;

    if (gAddressFamily == AF_INET)
    {
        icmpv4 = (struct icmp *)buf;
        icmpv4->icmp_cksum = 0;
        icmpv4->icmp_cksum = checksum((unsigned short *)buf, packetlen);
    }
    else if (gAddressFamily == AF_INET6)
    {
        icmpv6 = (struct icmp6_hdr *)buf;
        icmpv6->icmp6_cksum = 0;
        icmpv6->icmp6_cksum = icmp6Checksum((unsigned short *)buf, packetlen);
    }
}


/**
 * Wrapper to fill ICMPv4 and ICMPv6 headers
 *
 * @param pack_no sequence number to be filled in headers.
 * @return packsize length of the packet.
 */
int pack(int pack_no)
{
    int packsize;

    if (gAddressFamily == AF_INET)
    {
        packsize = initIcmp4Header(sendpacket, datalen, pack_no);
    }
    else if (gAddressFamily == AF_INET6)
    {
        packsize = initIcmp6Header(sendpacket, datalen, pack_no);
    }
    ComputeIcmpChecksum(sendpacket, packsize);

    return packsize;
}


/**
 * Prints the RTT value of the received ECHO REPLY
 *
 * @param buffer cointaing the packet.
 * @param len length of the packet.
 * @param tvrecv structure containing the timeval of the received packet.
 */
void printRtt(char *buf, int len, struct timeval *tvrecv)
{
    struct ip *ip;
    struct ip6_hdr *ip6;
    struct icmp *icmp;
    struct icmp6_hdr *icmp6;
    struct timeval *tvsend;
    char *datapart = NULL;
    int iphdrlen;
    float rtt;

    if (gAddressFamily == AF_INET)
    {
        ip = (struct ip*)buf;
        iphdrlen = sizeof(struct ip);

        icmp = (struct icmp*)(buf + iphdrlen);
        len -= iphdrlen;

        if(len > sizeof(struct icmp))
        {
            if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
            {
                tvsend = (struct timeval*)icmp->icmp_data;
                rtt = diff_ms(tvsend, tvrecv);
                if(!stop)
                {
                    nreceived++;
                    printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", len, inet_ntoa(faddr.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
                }
            }
            else if(icmp->icmp_type == 11) // ICMP_TIME_EXCEEDED 11
            {
                printf("Time exceeded\n");
            }
        }
    }
    else if(gAddressFamily == AF_INET6)
    {
        ip6 = (struct ip6_hdr*)buf;
        iphdrlen = sizeof(struct ip6_hdr);

        icmp6 = (struct icmp6_hdr*)(buf + iphdrlen);
        len -= iphdrlen;

        if(len > sizeof(struct icmp6_hdr))
        {
            if((icmp6->icmp6_type == ICMP6_ECHO_REPLY) && (ntohs(icmp6->icmp6_dataun.icmp6_un_data16[0]) == pid))
            {
                tvsend = (struct timeval*)((char *)buf + iphdrlen + sizeof(struct icmp6_hdr));
                rtt = diff_ms(tvsend, tvrecv);
                if(!stop)
                {
                    nreceived++;
                    printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", len, inet_ntoa(faddr.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
                }
            }
            else if(icmp6->icmp6_type == ICMP6_TIME_EXCEEDED)
            {
                printf("Time exceeded\n");
            }
        }
    }
}


/**
 * Finds the IP of the provited hostname
 *
 * @param host hostname.
 * @return 0 if success or -1 if error.
 */
int lookup_host(const char *host)
{
    struct addrinfo hints, *res;
    int errcode;
    char addrstr[100];
    void *ptr;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo (host, NULL, &hints, &res);
    if (errcode != 0)
    {
        perror ("getaddrinfo");
        return(-1);
    }

    while(res)
    {

        switch (res->ai_family)
        {
            case AF_INET:
                memcpy(&(daddr.sin_addr), &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(struct in_addr));
                break;
            case AF_INET6:
                memcpy(&(daddr6.sin6_addr), &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
                break;
        }
        res = res->ai_next;
    }
    return(0);
}


/**
 * Calculate the checksum of the ICMPv6 pseudo header
 *
 * @param buffer buffer containing the packet.
 * @param icmplen length of the packet.
 * @return checksum of the ICMPv6 header.
 */
unsigned short icmp6Checksum(unsigned short *buffer, int icmplen)
{
    char tmp[PACKET_SIZE] = {'\0'}, *ptr = NULL, proto = 0;
    int total, length, i;

    // We use a temporary buffer to calculate the pseudo header.
    ptr = tmp;
    total = 0;

    // Copy source address
    memcpy(ptr, &self_addr6.sin6_addr, sizeof(struct in6_addr));
    ptr   += sizeof(struct in6_addr);
    total += sizeof(struct in6_addr);

    // Copy destination address
    memcpy(ptr, &daddr6.sin6_addr, sizeof(struct in6_addr));
    ptr   += sizeof(struct in6_addr);
    total += sizeof(struct in6_addr);

    // Copy ICMP packet length
    length = htonl(icmplen);

    memcpy(ptr, &length, sizeof(length));
    ptr   += sizeof(length);
    total += sizeof(length);

    // Zero the 3 bytes
    memset(ptr, 0, 3);
    ptr   += 3;
    total += 3;

    // Copy next hop header
    proto = IPPROTO_ICMPV6;

    memcpy(ptr, &proto, sizeof(proto));
    ptr   += sizeof(proto);
    total += sizeof(proto);

    // Copy the ICMP header and payload
    memcpy(ptr, buffer, icmplen);
    ptr   += icmplen;
    total += icmplen;

    for(i=0; i < icmplen%2 ;i++)
    {
        *ptr = 0;
        ptr++;
        total++;
    }
    return checksum((unsigned short *)tmp, total);
}


/**
 * Set TTL value
 *
 * @return 0 if success or -1 if error.
 */
int setTtl()
{
    int optlevel = 0,
        option = 0,
        rc = 0;

    if(gAddressFamily == AF_INET)
    {
        optlevel = IPPROTO_IP;
        option   = IP_TTL;
    }
    else if (gAddressFamily == AF_INET6)
    {
        optlevel = IPPROTO_IPV6;
        option   = IPV6_UNICAST_HOPS;
    }
    else
    {
        rc = -1;
    }

    if(rc == 0)
    {
        rc = setsockopt(sockfd, optlevel, option, (char *)&gTtl, sizeof(gTtl));
        if (rc < 0)
        {
            fprintf(stderr, "SetTtl: setsockopt failed: %d\n", rc);
        }
    }

    return rc;
}
