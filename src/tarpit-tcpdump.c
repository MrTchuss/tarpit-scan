#define _DEFAULT_SOURCE

#include <tarpit-scan.h>

#include <pcap.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#include <unistd.h>

static void capture_callback(u_char *arg UNUSED , const struct pcap_pkthdr *header UNUSED, const u_char *packet)
{
	struct ip *ip;
	struct tcphdr *tcp;
	char *src;
	int open = 1;

	ip = (struct ip*)(packet+sizeof(struct ether_header));
	tcp = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));

	src = inet_ntoa(ip->ip_src);

	if (check_win_size && ntohs(tcp->th_win) < 10)
		open = 0;

	if (open)
		printf("%s:%d open\n", src, ntohs(tcp->th_sport));
	fflush(stdout);
}

#define SYNACK_FILTER "(ip src %s) and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)"
#define FINACK_FILTER "(ip src %s) and (tcp[tcpflags] & tcp-fin != 0) and (tcp[tcpflags] & tcp-ack != 0)"

static char *prepare_filter(char *ip)
{
	char base_exp[BUFSIZ];
	char *filter_exp;
	ssize_t size;

	/* prepare filter */
	if (check_win_size)
		strcpy(base_exp, SYNACK_FILTER);
	else
		strcpy(base_exp, FINACK_FILTER);

	if ((size = snprintf(NULL, 0, base_exp, ip)) < 0) {
		PERROR("-E- snprintf");
		return NULL;
	}

	if (!(filter_exp = malloc(size+1))) {
		perror("-E- malloc");
		abort();
	}

	if (snprintf(filter_exp, size+1, base_exp, ip) < 0) {
		PERROR("-E- snprintf");
		return NULL;
	}
	return filter_exp;
}


int tarpit_sniff(char *ip)
{
	pcap_t *pcap;			/* Session pcap */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp;
	int loop;
	int ret = -1;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */


	/* Define the device */
	if (optdev) {
		dev = optdev;
	} else if (!(dev = pcap_lookupdev(errbuf))) {
		fprintf(stderr, "-E- Couldn't find default device: %s\n", errbuf);
		return -1;
	}
	DBG(dev);

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "-W- Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	if (!(pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf))) {
		fprintf(stderr, "-E- Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (!(filter_exp = prepare_filter(ip)))
		goto error;
	DBG(filter_exp);

	/* Compile and apply the filter */
	if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "-E -Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		goto error;
	}

	if (pcap_setfilter(pcap, &fp) == -1) {
		fprintf(stderr, "-E- Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		goto error;
	}

	/* process sync */
	DBG("ready");
	if (close(pfd[1]) == -1) {
		PERROR("-W- Error synchronizing");
	}

	/* timeout, and die, in opttimeout seconds */
	alarm(opttimeout);

	/* Grab packets and display which are open*/
	while ((loop = pcap_loop(pcap, 65535, capture_callback, NULL)) >= 0);
	if (loop == -1) {
		fprintf(stderr, "-E- pcap_loop error\n");
		goto error;
	} else if (loop == -2) {
		/* breakloop was called */
	}
	DBG("DONE");

	ret = 0;
error:
	/* And close the session */
	pcap_close(pcap);

	return ret;
}

