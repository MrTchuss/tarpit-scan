#include <tarpit-scan.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>

#include <stdio.h>

#include <string.h>


static int sock_dorst(int sockfd)
{
	struct linger lin;
	lin.l_onoff = 1;
	lin.l_linger = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER,(void*)(&lin), sizeof(struct linger)) == -1) {
		PERROR("-E- setsockopt");
		return -1;
	}
	return 0;
}


static int sock_set_src_port(int sockfd, unsigned short src_port)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(src_port);
	if (get_ip_addr(&addr.sin_addr.s_addr) < 0)
		return -1;

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0) {
		PERROR("bind");
		return -1;
	}
	return 0;
}


int tarpit_connect(const char *ip, unsigned short port, unsigned short src_port)
{
	int sockfd;
	struct sockaddr_in addr;
	int ret = -1;

	if (!(sockfd = socket(AF_INET, SOCK_STREAM, 0))) {
		PERROR("-E- socket");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(port);
	/* do RST instead of FIN */
	if (reset && sock_dorst(sockfd) < 0)
		goto end;

	if (src_port && sock_set_src_port(sockfd, src_port) < 0)
		goto end;

	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))) {
		printf("-E- connect to port %u", port);
		PERROR("");
		goto end;
	}
	ret = 0;
end:
	if (close(sockfd) < 0) {
		PERROR("-E- Cannot close socket in tarpit_connect");
		return -1;
	}
	return ret;
}

