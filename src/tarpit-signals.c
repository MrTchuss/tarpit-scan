#include <tarpit-scan.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>

void chld_hdlr(int sig UNUSED)
{
	int serrno = errno;

	/* reap all child processes */
	while (waitpid(WAIT_ANY, NULL, WNOHANG) > 0)
		child_alive = 0;

	errno = serrno;
}

int set_chld_hdlr(void)
{
        struct sigaction sa;
        sa.sa_flags = 0;
        sa.sa_handler = chld_hdlr;
        if (sigemptyset(&sa.sa_mask)) {
                PERROR("-W- sigemptyset");
                return -1;
        }
        if (sigaction(SIGCHLD, &sa, NULL)) {
                PERROR("-W- sigaction");
                return -1;
        }
        return 0;
}

