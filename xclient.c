#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "eap.h"

#define  PID_FILE  "/var/run/xclient.pid"

void usage(char *name)
{
	printf("Just work xclient compatible with H3C iNode v5.0\n");
	printf("Desgined for Linux based system\n");
	printf("harl@qq.com ©2013\n");
	printf("usage: %s -i interface -u user -p password [-g log_file] [-m]\n", name);
	printf("-m means using multicast\n");
}

void xclient_exit()
{
	unlink(PID_FILE);
	exit(0);
}

int main(int argc, char **argv)
{
	char *dev = NULL;
	char *user = NULL;
	char *passwd = NULL;
	char *log_file = NULL;
	char ch;
	int  multicast = 0;
	
	signal(SIGCHLD, SIG_IGN);
	
	int pid_file = open(PID_FILE, O_RDWR|O_CREAT, 0644);
	if (pid_file < 0) {
		printf("open lock file failed\n");
		exit(EXIT_FAILURE);
	}
	int lock_result = lockf(pid_file, F_TEST, 0);
	if (lock_result < 0) {
		printf("xclient is already running\n");
		exit(EXIT_FAILURE);
	}
	
	opterr = 0; //disable getopt() output
	while ((ch = getopt(argc, argv, "i:u:p:g:m")) != -1) {
		switch(ch) {
			case 'i':
				dev = optarg;
				break;
			case 'u':
				user = optarg;
				break;
			case 'p':
				passwd = optarg;
				break;
			case 'g':
				log_file = optarg;
				break;
			case 'm':
				multicast++;
				break;
			default:
				goto usage;
		}
	}

	if (dev == NULL || user == NULL || passwd == NULL)
		goto usage;

	if (log_file == NULL)
		log_file = "/dev/null";

	pid_t pid = fork();
	if (pid != 0) {
		char p[16];
		sprintf(p, "%ld\n", (long)pid);
		ftruncate(pid_file, 0);
		write(pid_file, p, strlen(p) + 1);
		exit(0);
	}

	//child process
	if (setuid(0) != 0) {
		printf("Need to be root\n");
		exit(EXIT_FAILURE);
	}
	
	lock_result = lockf(pid_file, F_LOCK, 0);
	if (lock_result < 0) {
		printf("lock pid file failed\n");
		exit(EXIT_FAILURE);
	}
	
	signal(SIGTERM, xclient_exit);

	setsid();
	chdir("/");
	umask(0);

	int fd = open(log_file, O_RDWR|O_CREAT|O_TRUNC, 0666);
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	close(fd);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	EAP *eap = eap_open(dev, user, passwd);
	eap->multicast = multicast;
	while(1) {
		if (eap->retry_times > 3) {
			sleep(60);
			eap->retry_times = 0;
		}

		eap_send_start(eap);
		eap_event_loop(eap);
		sleep(10);
	}
	eap_release(eap);
	close(pid_file);
	return 0;

usage:
	usage(*argv);
	exit(EXIT_FAILURE);
}
