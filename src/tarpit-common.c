#include <tarpit-scan.h>

#include <pcap/pcap.h>

#include <netinet/in.h>

#include <string.h>


uint16_t get_tcp_wmem(void)
{
	uint16_t tcp_wmem;
#ifndef linux
	tcp_wmem = DEFAULT_TCP_WIN_SIZE;
#else
	FILE *fptr;
	char buffer[BUFSIZ];

	if (!(fptr = fopen("/proc/sys/net/ipv4/tcp_wmem", "r"))) {
		fprintf(stderr, "-W- Cannot read system default window size. Defaulting to %u\n", DEFAULT_TCP_WIN_SIZE);
		return (uint16_t)DEFAULT_TCP_WIN_SIZE;
	}

	if (!fgets(buffer, BUFSIZ, fptr)) {
		fprintf(stderr, "-W- Cannot read system default window size. Defaulting to %u\n", DEFAULT_TCP_WIN_SIZE);
		fclose(fptr);
		return (uint16_t)DEFAULT_TCP_WIN_SIZE;
	}
	fclose(fptr);

#define SYSCTL_DELIM "\t "
	strtok(buffer, SYSCTL_DELIM);
	tcp_wmem = (uint16_t)strtoul(strtok(NULL, SYSCTL_DELIM), NULL, 10);
#undef SYSCTL_DELIM
#endif

	return tcp_wmem;
}


int get_ip_addr(in_addr_t *ip)
{
	char *dev;
	pcap_if_t *pdev;
	pcap_addr_t *addr;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;

	/* Define the device */
	if (!optdev)
		dev = pcap_lookupdev(errbuf);
	else
		dev = optdev;

	if (dev == NULL) {
		fprintf(stderr, "-E- Find default device failed in file %s:%d: %s\n", __FILE__, __LINE__, errbuf);
		return -1;
	}

	if ((pcap_findalldevs(&alldevs, errbuf))) {
		printf("-E- findalldevs failed in file %s:%d: %s\n", __FILE__, __LINE__, errbuf);
		return -1;
	}

	for (pdev = alldevs; pdev != NULL; pdev = pdev->next) {
		if (!strcmp(pdev->name, dev)) {
			for (addr = pdev->addresses; addr != NULL; addr = addr->next) {
				if (addr->addr->sa_family == AF_INET) {
					*ip = ((struct sockaddr_in *)(addr->addr))->sin_addr.s_addr;
					/*printf("%s: %s\n", dev, inet_ntoa(((struct sockaddr_in *)(addr->addr))->sin_addr));*/
				}
			}
		}
        }

	pcap_freealldevs(alldevs);
	return 0;
}

