#ifndef TARPIT_SCAN
#define TARPIT_SCAN

#ifdef DEBUG
#define DBG(x)\
   do {\
      puts(x);\
   } while(0)
#else
#define DBG(x)
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define PERROR(x) \
        perror(x " failed in file " __FILE__ ":" TOSTRING(__LINE__))

#define UNUSED __attribute__((unused))


#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <signal.h>

#define DEFAULT_TCP_WIN_SIZE 512

extern int pfd[];
extern uint8_t ports_bitmap[];
extern int opttimeout;
extern char *optdev;
extern int check_win_size;
extern int reset;
extern unsigned short src_port;
extern int syn;
extern int _connect;
extern sig_atomic_t child_alive;

uint16_t get_tcp_wmem(void);
int get_ip_addr(in_addr_t *ip);
int tarpit_connect(const char *ip, unsigned short port, unsigned short src_port);
int tarpit_syn(const char *ip, unsigned short port, unsigned short src_port);
int tarpit_sniff(char *ip);

#endif /* ifndef TARPIT_SCAN */

