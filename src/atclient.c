#include "atclient.h"
#define SERVER_PORT_1 3848
#define SERVER_PORT_2 3850
#define SERVER_PORT_3 3849
#define VERSION "atclient version:1.0.0"
#define AUTHOR "Author: lyq1996"
#define INIT_SERVER "1.1.1.8"

void usage()
{
	puts(VERSION);
	puts(AUTHOR);
	puts("Usage:[Options]");
	puts("\t-u | --username\n\t\tUser name");
	puts("\t-p | --password\n\t\tUser password");
	puts("\t-d | --device\n\t\tNetwork card interface");
	puts("\t-i | --host\n\t\tServer IP");
	//puts("\t-q | --quit\n\t-e | --exit\n\t-l | --leave\n\t\tQuit procedure, leave Internet");  not finish yet
	exit(0);
}

void check_arg(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> psu;
	int c, index = 0;
	struct option options[] = {
		{"username", 1, NULL, 'u'},
		{"password", 1, NULL, 'p'},
		{"device", 1, NULL, 'd'},
		{"host", 1, NULL, 'i'},
		{NULL, 0, NULL, 0}
	};
	
	while ((c = getopt_long(argc, argv, "u:p:d:i:s:", options, &index)) != -1)
	{
			switch (c) {
				case 'u':
					pui -> usr = optarg;
					break;
				case 'p':
					pui -> pw = optarg;
					break;
				case 'd':
					strcpy(pui -> dev, optarg);
					break;
				case 'i':
					strcpy(pui -> host_ip, optarg);
					break;
				default:
					usage();
					break;
		}
	}
}

#ifdef __linux__
int Init(struct infoset *const pinfo)
{
	int sockfd;
	struct usrinfoSet *psu = pinfo->psu;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("[ERROR]");
		exit(1);
	}
	struct ifreq addr;
	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, psu->dev);
	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1)
	{
		perror("[ERROR]");
		exit(1);
	}
	strcpy(psu->local_ip, inet_ntoa(((struct sockaddr_in *)&addr.ifr_addr)->sin_addr));
	memset(&addr, 0, sizeof addr);
	strcpy(addr.ifr_name, (*psu).dev);

	if (ioctl(sockfd, SIOCGIFHWADDR, (char *)&addr) == -1)
	{
		perror("[ERROR]");
		exit(1);
	}
	memcpy(psu->mac, addr.ifr_hwaddr.sa_data, 0x6);
	return sockfd;
}
#elif __APPLE__
#include "TargetConditionals.h"
#ifdef TARGET_OS_MAC
#include <netinet/in.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
int Init(struct infoset *const pinfo)
{
	int sockfd;
	struct usrinfoSet *psu = pinfo->psu;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("[ERROR]");
		exit(1);
	}
	struct ifreq addr;
	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, psu->dev);
	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1)
	{
		perror("[ERROR]");
		exit(1);
	}
	strcpy(psu->local_ip, inet_ntoa(((struct sockaddr_in *)&addr.ifr_addr)->sin_addr));

	struct ifaddrs *if_addrs = NULL;
	struct ifaddrs *if_addr = NULL;
	if (0 == getifaddrs(&if_addrs))
	{
		for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next)
		{
			if (strcmp(if_addr->ifa_name, addr.ifr_name) == 0)
			{
				if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK)
				{
					struct sockaddr_dl *sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
					if (6 == sdl->sdl_alen)
					{
						memcpy(psu->mac, LLADDR(sdl), sdl->sdl_alen);
					}
				}
			}
		}
		freeifaddrs(if_addrs);
		if_addrs = NULL;
	}
	else
	{
		perror("[ERROR]");
		exit(1);
	}
	return sockfd;
}
#endif
#endif
void pktEncrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		int i;
		for (i = 0; i < len; i++) {
			s[i] = (s[i] & 0x1) << 7 | (s[i] & 0x2) >> 1 |(s[i] & 0x4) << 2|(s[i] & 0x8) << 2|(s[i] & 0x10) << 2|(s[i] & 0x20) >> 2|(s[i] & 0x40) >> 4|(s[i] & 0x80) >> 6;
		}
	}
}

void pktDecrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		int i;
		for (i = 0; i < len; i++) {
			s[i] = (s[i] & 0x1) << 1 | (s[i] & 0x2) << 6 |(s[i] & 0x4) << 4|(s[i] & 0x8) << 2|(s[i] & 0x10) >> 2|(s[i] & 0x20) >> 2|(s[i] & 0x40) >> 2|(s[i] & 0x80) >> 7;
		}
	}
}

/* this fuction is not finished yet.
void try_get_server(int sockfd,struct infoset * const pinfo){
	char md5[0x10] = {0x0};
	int  md5len = 0x10;
	char *pkt, *ppkt, *tmphost;
	struct usrinfoSet *psu = pinfo -> psu;
	struct sockaddr_in *pss = pinfo -> pss;
	int sendbytes = 51;
	
	int iplen = strlen(psu -> local_ip), maclen = 0x6;
	pkt = (char *)calloc(sendbytes, sizeof(char));
	ppkt = pkt;
	*ppkt++ = 0x0c;
	*ppkt++ = sendbytes;
	ppkt += 0x10;
	
	*ppkt++ = 0x08;
	*ppkt++ = 0x07;
	*ppkt++ = 0x00;
	*ppkt++ = 0x01;
	*ppkt++ = 0x02;
	*ppkt++ = 0x03;
	*ppkt++ = 0x04;
	
	*ppkt++ = 0x9;
	*ppkt++ = 0x12;
	memcpy(ppkt, psu -> local_ip, iplen);
	ppkt += iplen;

	ppkt += 0x10 - iplen;
	
	*ppkt++ = 0x07;
	*ppkt++ = maclen+2;
	memcpy(ppkt, psu -> mac, maclen);
	ppkt += maclen;
	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);
	pktEncrypt(pkt, pkt[1]);

	memset(pss, 0x0, sizeof(struct sockaddr_in));
	pss -> sin_family = AF_INET;
	pss -> sin_port = htons(SERVER_PORT_2);
	pss -> sin_addr.s_addr = inet_addr(INIT_SERVER);
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("sendto");
			exit(1);
		}
	puts("Send Search Server IP Packet Success!\n");
	free(pkt);
	
	int pkt_recv_size = 0x100;
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("Recvice Size Error!\n");
		exit(0);
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			exit(0);
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);
	get_server(pkt_recv,psu);
	free(pkt_recv);
}

void get_server(){

}

*/

bool try_get_service(int sockfd, struct infoset * const pinfo){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;
	struct sockaddr_in *pss = pinfo -> pss;
	unsigned int maclen = 0x6, md5len = 0x10, sendbytes = 0x21;

	pkt = (char *)calloc(sendbytes, sizeof(char));
	ppkt = pkt;
	*ppkt++ = 0x07;
	*ppkt++ = sendbytes;
	ppkt += 0x10;	//0x00*16 for md5 hash
	
	*ppkt++ = 0x08;
	*ppkt++ = 0x07;
	*ppkt++ = 0x00;	//for fade session
	*ppkt++ = 0x01;
	*ppkt++ = 0x02;
	*ppkt++ = 0x03;
	*ppkt++ = 0x04;
	
	*ppkt++ = 0x07;
	*ppkt++ = maclen + 0x2;
	memcpy(ppkt, psu -> mac, maclen);
	ppkt += maclen;
	
	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);
	pktEncrypt(pkt, pkt[1]);

//******************---------------socket init----------------***************//
	memset(pss, 0x0, sizeof(struct sockaddr_in));	//socket init
	pss -> sin_family = AF_INET;
	pss -> sin_port = htons(SERVER_PORT_1);
	pss -> sin_addr.s_addr = inet_addr(psu -> host_ip);
	
	struct timeval timeout;   //socket timeout   
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
				sizeof(timeout)) < 0)
		puts("[atclient]:Set sockopt Failed\n");

	if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
				sizeof(timeout)) < 0)
		puts("[atclient]:Set sockopt Failed\n");

//******************---------------socket init----------------***************//
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("[ERROR]");
			exit(1);
		}
	puts(VERSION);
	puts(AUTHOR);
	puts("[atclient]:Send Search Service Packet...Waiting For Response...");
	free(pkt);		
	int pkt_recv_size = 0x1000;	//max recvice packet size
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
		
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[ERROR]:Recvice Size Error!");
		puts("[NOTICE]:Search Service Failed!Retry...");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[ERROR]:Recvice Size Error!");
			puts("[NOTICE]:Search Service Failed!Retry...");
			free(pkt_recv);
			return false;
		}
		pktDecrypt(pkt_recv, pkt_recv_size);
		memcpy(md5, pkt_recv + 2, md5len);
		memset(pkt_recv + 2, 0x0, md5len);
		get_service(pkt_recv,psu);
		free(pkt_recv);
		return true;
	}
	
}

void get_service(const char * const pkt, struct usrinfoSet * psu)
{
	const char * ppkt = pkt;
	ppkt += 0x12;
	if ( * ppkt == 0xa ) {
		++ ppkt;
		psu -> service = (char *)calloc(*ppkt - 1, sizeof(char));
		strncpy(psu -> service, ppkt + 1, (*ppkt) -2 );
		printf("[atclient]:Get Service Type: %s\n",psu -> service);
}
else{
	puts("[ERROR]:This Software is not Suitable for you.");
	exit(1);
}
}

bool try_login(int sockfd, struct infoset * const pinfo){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;
	
	unsigned int iplen = strlen(psu -> local_ip), usrlen = strlen(psu -> usr), pwdlen = strlen(psu -> pw), serlen = strlen(psu -> service), md5len = 0x10, maclen = 0x06;
	unsigned int sendbytes = 44 + iplen + usrlen + pwdlen + serlen;

	pkt = (char *)calloc(sendbytes, sizeof(char));
	ppkt = pkt;
	*ppkt++ = 0x01;
	*ppkt++ = sendbytes;
	ppkt += 0x10;	//0x00*16 for md5 hash

	*ppkt++ = 0x07;
	*ppkt++ = maclen + 0x2;
	memcpy(ppkt, psu -> mac, maclen);
	ppkt += maclen;
	
	*ppkt++ = 0x01;
	*ppkt++ = usrlen + 0x2;
	memcpy(ppkt, psu -> usr, usrlen);
	ppkt += usrlen;
	
	*ppkt++ = 0x02;
	*ppkt++ = pwdlen + 0x2;
	memcpy(ppkt, psu -> pw, pwdlen);
	ppkt += pwdlen;
	
	*ppkt++ = 0x9;
	*ppkt++ = iplen + 0x2;
	memcpy(ppkt, psu -> local_ip, iplen);
	ppkt += iplen;
	
	*ppkt++ = 0xa;
	*ppkt++ = serlen + 0x2;
	memcpy(ppkt, psu -> service, serlen);
	ppkt += serlen;
	
	*ppkt++ = 0xe;
	*ppkt++ = 0x3;
	*ppkt++ = 0x0;	//dhcp
	*ppkt++ = 0x1f;
	*ppkt++ = 0x7;
	*ppkt++ = 51;	//version 3.6.4
	*ppkt++ = 46;
	*ppkt++ = 54;
	*ppkt++ = 46;
	*ppkt++ = 52;

	
	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);	//md5
	pktEncrypt(pkt, pkt[1]);	//encrypt it
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("[ERROR]");
			exit(1);
		}
	puts("[atclient]:Send Login Packet Success...Waiting For Response...");
	free(pkt);
	
	int pkt_recv_size = 0x1000;	//max recvice packet size
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[ERROR]:Recvice Size Error!");
		puts("[NOTICE]:Login Failed!Retry...");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[ERROR]:Recvice Size Error!");
			puts("[NOTICE]Login Failed!Retry...");
			free(pkt_recv);
			return false;
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);

	bool login_status = (bool)pkt_recv[0x14];
	if (login_status){
		get_session(pkt_recv, psu);
		free(pkt_recv);
		puts("[atclient]:Login Success!");
		return login_status;
	}
	else{
		puts("[atclient]:Login Failed!Retry...");
		free(pkt_recv);
		return login_status;
	}
}

void get_session(const char * const pkt, struct usrinfoSet * psu)
{
	const char * ppkt = pkt;
	ppkt += 0x15;
	if ( *ppkt == 0x8 ) {
		++ ppkt;
		psu -> session = (char *)calloc(*ppkt + 1, sizeof(char));
		strncpy(psu -> session, ppkt + 1, *ppkt);
		//printf("[atclient]:Session -> %s\n",psu -> session);
}
}

bool try_breathe(int sockfd, struct infoset * const pinfo ,long index){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;	
	unsigned int iplen = strlen(psu -> local_ip),sessionlen = strlen(psu -> session), md5len = 0x10, maclen = 0x06, sendbytes = 88 + sessionlen;	
	unsigned int index_1 = index_bits1(index), index_2 = index_bits2(index), index_3 = index_bits3(index), index_4 = index_bits4(index);
	
	pkt = (char *)calloc(sendbytes, sizeof(char));
	ppkt = pkt;
	*ppkt++ = 0x03;
	*ppkt++ = sendbytes;
	ppkt += 0x10;	//0x00 * 16 for md5 hash

	*ppkt++ = 0x08;
	*ppkt++ = sessionlen + 2;
	memcpy(ppkt, psu -> session, sessionlen);
	ppkt += sessionlen;
	
	*ppkt++ = 0x9;
	*ppkt++ = 0x12;
	memcpy(ppkt, psu -> local_ip, iplen);
	ppkt += iplen;
	ppkt += 0x10 - iplen;
	
	*ppkt++ = 0x07;
	*ppkt++ = maclen + 2;
	memcpy(ppkt, psu -> mac, maclen);
	ppkt += maclen;
	
	*ppkt++ = 0x14;	/*index*/
	*ppkt++ = 0x06;
	*ppkt++ = index_4;
	*ppkt++ = index_3;
	*ppkt++ = index_2;
	*ppkt++ = index_1;
	
	*ppkt++ = 0x2a;	/*block*/
	*ppkt++ = 0x06;
	ppkt += 0x04;
	*ppkt++ = 0x2b;
	*ppkt++ = 0x06;
	ppkt += 0x04;
	*ppkt++ = 0x2c;
	*ppkt++ = 0x06;
	ppkt += 0x04;
	*ppkt++ = 0x2d;
	*ppkt++ = 0x06;
	ppkt += 0x04;
	*ppkt++ = 0x2e;
	*ppkt++ = 0x06;
	ppkt += 0x04;
	*ppkt++ = 0x2f;
	*ppkt++ = 0x06;
	ppkt += 0x04;
	//printf("[atclient]:index -> %d %d %d %d",index_4,index_3,index_1,index_1);

	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);	//md5
	pktEncrypt(pkt, pkt[1]);	//encrypt it
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("[ERROR]");
			exit(1);
		}
	puts("[atclient]:Send Breathe Packet Success...Wait For Response...");
	free(pkt);
	
	int pkt_recv_size = 0x1000;	//max recvice packet size
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[ERROR]:Recvice Size Error!\n");
		puts("[ERROR]:Breathe Failed!Retry...");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[ERROR]:Recvice Size Error!");
			puts("[NOTICE]:Breathe Failed!Retry...");
			free(pkt_recv);
			return false;
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);

	bool login_status = (bool)pkt_recv[0x14];
	if (login_status){
		puts("[atclient]:Breathe Success");
		free(pkt_recv);
		return login_status;
	}
	else{
		puts("[atclient]:Breathe Failed!Retry...");
		free(pkt_recv);
		return login_status;
	}
}

unsigned int index_bits4(long index){
	unsigned int tmp = index >> 24;
	return tmp;
}
unsigned int index_bits3(long index){
	unsigned int tmp = index << 8;
	tmp = tmp >> 24;
	return tmp;
}
unsigned int index_bits2(long index){
	unsigned int tmp = index << 16;
	tmp = tmp >> 24;
	return tmp;
}
unsigned int index_bits1(long index){
	unsigned int tmp = index << 24;
	tmp = tmp >> 24;
	return tmp;
}


int main(int argc, char *argv[]) 
{
	struct usrinfoSet usrinfo;
	struct sockaddr_in server_addr;
	
	struct infoset info;	//define struct
	
	info.pss = &server_addr;
	info.psu = &usrinfo;
	
	memset(&usrinfo, 0x0, sizeof(struct usrinfoSet));	//clear
	if (argc == 9){		
		check_arg(argc, argv, &info);
		while(1){
			int sockfd = Init(&info);
			bool search_status = try_get_service(sockfd, &info);
			while(!search_status){
				sleep(5);
				search_status = try_get_service(sockfd, &info);
			}
			bool login_status = try_login(sockfd, &info);
			while (!login_status){
				sleep(5);
				login_status = try_login(sockfd, &info);
			}
			long index = 0x10000000;
			bool breath_status = try_breathe(sockfd, &info, index);
			while (breath_status){
				index += 3;
				sleep(20);
				breath_status = try_breathe(sockfd, &info, index);
			}
			close(sockfd);
			}
		}
	else{	
		usage();
	}
}