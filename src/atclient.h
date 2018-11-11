#include <stdio.h>	
#include <string.h>	
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "md5.h"
#include <sys/time.h>
#include <time.h>


struct usrinfoSet{
	char * usr;
	char * pw;
	char * session;
	char * service;
	char dev[0xc];
	char local_ip[0x10];
	char host_ip[0x10];
	char mac[0x8];
};

struct infoset{
	struct sockaddr_in * pss;
	struct usrinfoSet * psu;
};