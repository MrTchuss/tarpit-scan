#include <tarpit-scan.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <string.h> /* memset */

#include <sys/wait.h>

#include <libgen.h> /* basename */

#include <getopt.h>

#include <ctype.h> /* isdigit */

#include <time.h>

#include <limits.h>

#include <fcntl.h>

#include <arpa/inet.h> /* inet_pton */

#include <errno.h>

#define PORT_BITMAP_SIZE (USHRT_MAX+1)/8

int pfd[2];                      /* File descriptors for pipe */
uint8_t ports_bitmap[PORT_BITMAP_SIZE];
int opttimeout = 5;
char *optdev = NULL;
int check_win_size = 1;
int reset = 0;
unsigned short src_port = 0;
int syn = 1;
sig_atomic_t child_alive = 0;


static void syntax(char *name)
{
	printf("syntax: %s [--honeypot] [--iface <iface>] [--tmout <timeout>] [--help] [--syn] [--connect] [--reset] --port <port range or sequence> <ip>\n", basename(name));
	exit(EXIT_FAILURE);
}

static void set_ports_bitmap(unsigned short port)
{
	ports_bitmap[port/8] |= (1<<(port % 8));
}

static int parse_ports(char *str)
{
	char *ptr, *endptr;
	unsigned int port, lastport;
	int isrange = 0;

	ptr = str;
	while (*ptr) {
		if (*ptr == '-') {
			isrange = 1;
			ptr ++;
		} else if (*ptr == ',') {
			ptr ++;
		} else if (isdigit(*ptr)) {
			port = strtoul(ptr, &endptr, 10);
			ptr = endptr;
			if (port == 0 || port > USHRT_MAX)
				return -1; /* invalid port */
			if (isrange) {
				unsigned int p;
				for (p = lastport ; p < port ; ++ p)
					set_ports_bitmap(p);
			}
			lastport = port;
			isrange = 0;
			set_ports_bitmap(port);
		} else {
			return -2; /* invalid symbol */
			ptr ++;
		}
	}
	if (0) {
		int i;
		for (i=0; i < PORT_BITMAP_SIZE; ++i) {
			printf("%.2x", ports_bitmap[i]);
		}
		puts("");
	}
	return 0;
}


static int open_out_file(char *filename)
{
	int fd;
	if (filename) {
		if ((fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP)) < 0) {
			PERROR("open");
			return -1;
		} else {
			if (dup2(fd, STDOUT_FILENO) < 0) {
				PERROR("-W- dup2");
			}
			if (close(fd) == -1) {
				PERROR("-W- close");
			}
			setbuf(stdout, NULL);
		}
	}
	return 0;
}

static int parse_args(int argc, char **argv)
{
	int c, ret, option_index, _src_port;
	static struct option long_options[] = {
		{"output", required_argument, 0, 'o'},
		{"iface", required_argument, 0, 'i'},
		{"ports", required_argument, 0, 'p'},
		{"tmout", required_argument, 0, 't'},
		{"honeypot", no_argument,      0, '0'},
		{"connect", no_argument,    0, 'c'},
		{"rst", no_argument,    0, 'r'},
		{"syn", no_argument,    0, 's'},
		{"source-port", required_argument, 0, '1'},
		{"help" , no_argument      , 0, 'h'},
		{0,0,0,0}
	};

	option_index = 0;
	while ((c = getopt_long(argc, argv, "o:i:p:t:hcrs", long_options, &option_index)) != -1) {
		switch (c) {
		case 'o':
			open_out_file(optarg);
			break;
		case 'r':
			reset = 1;
			break;
		case 's':
			syn = 1;
			break;
		case 'c':
			syn = 0;
			break;
		case '1':
			_src_port = atoi(optarg);
			if (_src_port <= 0 || _src_port >= UINT16_MAX) {
				fputs("-W- Invalid source port. Choosing random one.\n", stderr);
			} else
				src_port = _src_port;
			break;
		case '0':
			check_win_size = 0;
			syn = 0;
			break;
		case 'i':
			optdev = strdup(optarg);
			break;
		case 'p':
			ret = parse_ports(optarg);
			if (ret == -1) {
				fprintf(stderr, "-E- Invalid port (port == 0 or port greater than %d)\n", USHRT_MAX);
				return -1;
			}
			else if (ret == -2) {
				fputs("-E- Invalid port (invalid char)\n", stderr);
				return -1;
			}
			break;
		case 't':
			opttimeout = atoi(optarg);
			break;
		case '?':
		case 'h':
			syntax(argv[0]);
			break;
		default:
			abort();
		}
	}

	if (reset && syn) {
		fputs("-W- Cannot close the connection with a RESET in syn mode :) Discarding --reset\n", stderr);
		reset = 0;
	}

	if (reset && !check_win_size) {
		fputs("-W- Cannot use --reset when performing a check on window size. Discarding --reset\n", stderr);
		reset = 0;
	}

	if (!check_win_size && syn) {
		fputs("-W- Cannot perform a syn-scan when looking for FIN/ACK. Discarding --syn\n", stderr);
		syn = 0;
	}

	return 0;
}

static int mass_send(char *ip)
{
	unsigned short port;
	int (*tarpit_send)(const char *, unsigned short, unsigned short);
	tarpit_send = (syn)?tarpit_syn:tarpit_connect;

	for (port = 1; port > 0; ++ port) {
		/* port > 0 to avoid ushort rotation */
		if (ports_bitmap[port/8] & (1<<(port%8))) {
			/* printf("Sending port %d\n", port); */
			printf(".");
			fflush(stdout);
			tarpit_send(ip, port, src_port);
			/*if (tarpit_send(ip, port, src_port) < 0)
				return -1;*/
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	pid_t pid;
	char dummy;
	char *ip;
	struct in_addr addr;

	srandom(time(NULL));

	if (parse_args(argc, argv) < 0)
		return EXIT_FAILURE;

	if (optind != argc-1) {
		syntax(argv[0]);
	}
	ip = argv[optind];

	/* shall never return -1, as address family is hardcoded */
	if (!inet_pton(AF_INET, ip, &addr)) {
		fprintf(stderr, "-E- Invalid IPv4 address \"%s\"\n", ip);
		return EXIT_FAILURE;
	}

	if (pipe(pfd) == -1) {
		PERROR("-E- pipe");
		return EXIT_FAILURE;
	}

	switch ((pid = fork())) {
	case -1:
		PERROR("-E- fork");
		return EXIT_FAILURE;
	case 0:
		child_alive = 1;
		if (close(pfd[0]) < 0)
			PERROR("-W- Closing pipe read-end");
		if (tarpit_sniff(ip) < 0)
			exit(EXIT_FAILURE);
		/* should never go here */
		break;
	/* processes comminicates through a pipe */
	default:
		if (close(pfd[1]) < 0)
			PERROR("-W- Closing pipe write-end");

		if (read(pfd[0], &dummy, 1) != 0 && errno == EINTR) {
			printf("-E- Child process send us an error\n");
			return EXIT_FAILURE;
		}
		puts("#START");
		if (!mass_send(ip)) {
			sleep(opttimeout);
		}
		/* wait for child */
		waitpid(pid, NULL, 0);

		puts("#DONE");
		break;
	}

	return EXIT_SUCCESS;
}

