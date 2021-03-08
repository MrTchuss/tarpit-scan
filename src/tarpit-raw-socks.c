#define _DEFAULT_SOURCE

#include <tarpit-scan.h>

#include <stdint.h>

#include <netinet/tcp.h>

#include <stdlib.h>

#include <string.h>

#include <arpa/inet.h>

#include <stdio.h>

static unsigned short csum (unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}


static unsigned short tcp_cksum(const struct tcphdr *tcph, const char *ip)
{
	/* pseudo-header is only used to calculate TCP cksum */
	struct pseudo_hdr {
		u_int32_t src;
		u_int32_t dst;
		u_char mbz;
		u_char proto;
		u_int16_t len;
	};
	struct pseudo_hdr *phdr;
	unsigned char datagram[sizeof(struct tcphdr) + sizeof(struct pseudo_hdr)];

	memcpy(datagram, tcph, sizeof(struct tcphdr));
	phdr = (struct pseudo_hdr *) (datagram + sizeof(struct tcphdr));
	phdr->dst = inet_addr(ip);
	get_ip_addr(&phdr->src);
	phdr->mbz = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->len = ntohs(sizeof(struct tcphdr));
	return csum((unsigned short*)&datagram, sizeof(datagram)/2);
}


int tarpit_syn(const char *ip, unsigned short port, unsigned short src_port)
{
	struct tcphdr tcph;
	int sockfd, ip_hdrincl;
	struct sockaddr_in addr;

	memset(&tcph, 0, sizeof(struct tcphdr));

	tcph.th_sport = (!src_port)?htons(1 + random() % (UINT16_MAX-1)):htons(src_port);
	tcph.th_dport = htons(port);
	tcph.th_seq = htonl(random() % UINT32_MAX);
	/*tcph.th_ack = htonl(random() % UINT32_MAX); */
	tcph.th_ack = 0;
	tcph.th_off = 5;
	tcph.th_flags = TH_SYN;
	tcph.th_win = htons(get_tcp_wmem());
	tcph.th_urp = 0;

	tcph.th_sum = tcp_cksum(&tcph, ip);

	if (!(sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP))) {
		PERROR("-E- socket");
		return -1;
	}

	/* the ip layer is provided by the kernel */
	ip_hdrincl = 0;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &ip_hdrincl, sizeof(ip_hdrincl)) < 0) {
		PERROR("-E- setsockopt");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (sendto(sockfd, (unsigned char*)&tcph, sizeof(struct tcphdr), 0,
		(struct sockaddr*)&addr, sizeof(struct sockaddr)) < 0 ) {
		PERROR("-E- sendto");
		return -1;
	}

	return 0;
}

