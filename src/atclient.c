#include "atclient.h"
#define SERVER_PORT_1 3848
#define SERVER_PORT_2 3850
#define VERSION "Version:1.0.1"
#define INIT_SERVER "1.1.1.8"

static void usage()
{
	puts(VERSION);
	puts("Usage:[Options]");
	puts("\t-u | --username\n\t\tUser name");
	puts("\t-p | --password\n\t\tUser password");
	puts("\t-d | --device\n\t\tNetwork card interface");
	puts("\t-i | --host\n\t\tServer IP");
	puts("\t-s | --service\n\t\tService type");
	exit(1);
}

static void check_arg(int argc, char **argv, struct infoset * const pinfo, bool * argv_scheck, bool * argv_icheck)
{
	if(argc < 7){
		usage();
		exit(1);
	}

	struct usrinfoSet *psu = pinfo -> psu;
	int c, index = 0;
	struct option options[] = {
		{"username", 1, NULL, 'u'},
		{"password", 1, NULL, 'p'},
		{"device", 1, NULL, 'd'},
		{"host", 1, NULL, 'i'},
		{"service",1,NULL,'s'},
		{NULL, 0, NULL, 0}
	};

	while ((c = getopt_long(argc, argv, "u:p:d:i:s:", options, &index)) != -1)
	{
			switch (c) {
				case 'u':
					psu -> usr = optarg;
					break;
				case 'p':
					psu -> pw = optarg;
					break;
				case 'd':
					strcpy(psu -> dev, optarg);
					break;
				case 'i':
					strcpy(psu -> host_ip, optarg);
					* argv_icheck = true;
					break;
				case 's':
					psu -> service = optarg;
					* argv_scheck = true;
					break;
				default:
					usage();
					break;
		}
	}
}

#ifdef __linux__
static void ip_mac_init(struct infoset *const pinfo)
{
	int sockfd;
	struct usrinfoSet *psu = pinfo->psu;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("device init");
		exit(1);
	}
	struct ifreq addr;
	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, psu->dev);
	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1)
	{
		perror("device init");
		exit(1);
	}
	strcpy(psu->local_ip, inet_ntoa(((struct sockaddr_in *)&addr.ifr_addr)->sin_addr));
	
	memset(&addr, 0, sizeof addr);
	strcpy(addr.ifr_name, psu -> dev);
	if (ioctl(sockfd, SIOCGIFHWADDR, (char *)&addr) == -1)
	{
		perror("device init");
		exit(1);
	}
	memcpy(psu->mac, addr.ifr_hwaddr.sa_data, 0x6);
	close(sockfd);
}
#elif __APPLE__
#include "TargetConditionals.h"
#ifdef TARGET_OS_MAC
#include <netinet/in.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
static void ip_mac_init(struct infoset *const pinfo)
{
	int sockfd;
	struct usrinfoSet *psu = pinfo->psu;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("device init");
		exit(1);
	}
	struct ifreq addr;
	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, psu->dev);
	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1)
	{
		perror("device init");
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
		perror("device init");
		exit(1);
	}
	close(sockfd);
}
#endif
#endif
static int socket_init(struct infoset *const pinfo){
	int sockfd;
	struct usrinfoSet *psu = pinfo->psu;
	struct sockaddr_in *pss = pinfo -> pss;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket init");
		exit(1);
	}
	memset(pss, 0x0, sizeof(struct sockaddr_in));	//socket init
	pss -> sin_family = AF_INET;
	pss -> sin_port = htons(SERVER_PORT_1);
	pss -> sin_addr.s_addr = inet_addr(psu -> host_ip);
	
	struct timeval timeout;   //socket timeout   
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0){
			perror("socket init");
			exit(1);
	}
	return sockfd;
}
static void pktEncrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		int i;
		for (i = 0; i < len; i++) {
			s[i] = (s[i] & 0x1) << 7 | (s[i] & 0x2) >> 1 |(s[i] & 0x4) << 2|(s[i] & 0x8) << 2|(s[i] & 0x10) << 2|(s[i] & 0x20) >> 2|(s[i] & 0x40) >> 4|(s[i] & 0x80) >> 6;
		}
	}
}

static void pktDecrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		int i;
		for (i = 0; i < len; i++) {
			s[i] = (s[i] & 0x1) << 1 | (s[i] & 0x2) << 6 |(s[i] & 0x4) << 4|(s[i] & 0x8) << 2|(s[i] & 0x10) >> 2|(s[i] & 0x20) >> 2|(s[i] & 0x40) >> 2|(s[i] & 0x80) >> 7;
		}
	}
}

static bool get_server(struct infoset * const pinfo){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;
	struct sockaddr_in *pss = pinfo -> pss;
	int sendbytes = 51,md5len = 0x10,maclen = 0x6;
	int iplen = strlen(psu -> local_ip);
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

	for(int i=0;i<0x10-iplen;i++){
		*ppkt++ = 0;
	}//add zero
	
	*ppkt++ = 0x07;
	*ppkt++ = maclen+2;
	memcpy(ppkt, psu -> mac, maclen);
	ppkt += maclen;
	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);
	pktEncrypt(pkt, pkt[1]);

	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("get server IP");
		return false;
	}

//******************---------------socket init----------------***************//
	memset(pss, 0x0, sizeof(struct sockaddr_in));	//socket init
	pss -> sin_family = AF_INET;
	pss -> sin_port = htons(SERVER_PORT_2);
	pss -> sin_addr.s_addr = inet_addr(INIT_SERVER);
	
	struct timeval timeout;   //socket timeout   
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0){
			perror("get server IP");
			return false;
	}
//******************---------------socket init----------------***************//	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("get server IP");
			exit(1);
		}
	puts("[get server IP]:sended out a UDP packet to auto find server IP address.");
	free(pkt);
	
	int pkt_recv_size = 0x100;
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[get server IP]:timeout.");
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[get server IP]:Recvice size error!");
			free(pkt_recv);
			return false;
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);

	char * ppkt_i = pkt_recv;
	int ip_index = 0;
	for(int i=0;i<pkt_recv[1];i++){
		if(pkt_recv[i]==0x0c){
			ip_index = i;
		}
	}
	ppkt_i += ip_index;
	ppkt_i += 2;

	unsigned char ip_byte1 = *ppkt_i;
	ppkt_i++;
	unsigned char ip_byte2 = *ppkt_i;
	ppkt_i++;
	unsigned char ip_byte3 = *ppkt_i;
	ppkt_i++;
	unsigned char ip_byte4 = *ppkt_i;
	ppkt_i++;

	char ip_bytea1[3],ip_bytea2[3],ip_bytea3[3],ip_bytea4[3];
	ip_bytea1[0] = ip_byte1 / 100 + 0x30;
	ip_bytea1[1] = (ip_byte1 - (ip_byte1 / 100 * 100))/ 10 + 0x30;
	ip_bytea1[2] = ip_byte1 % 10 + 0x30;
	ip_bytea2[0] = ip_byte2 / 100 + 0x30;
	ip_bytea2[1] = (ip_byte2 - (ip_byte2 / 100 * 100))/ 10 + 0x30;
	ip_bytea2[2] = ip_byte2 % 10 + 0x30;
	ip_bytea3[0] = ip_byte3 / 100 + 0x30;
	ip_bytea3[1] = (ip_byte3 - (ip_byte3 / 100 * 100))/ 10 + 0x30;
	ip_bytea3[2] = ip_byte3 % 10 + 0x30;
	ip_bytea4[0] = ip_byte4 / 100 + 0x30;
	ip_bytea4[1] = (ip_byte4 - (ip_byte3 / 100 * 100))/ 10 + 0x30;
	ip_bytea4[2] = ip_byte4 % 10 + 0x30;
	
	char *pti = psu -> host_ip;
	for(int i=0;i<3;i++){
		if(ip_bytea1[i] != '0'){
			*pti = ip_bytea1[i];
			pti ++;
		}
		else{
			if (i==2){
				*pti = ip_bytea1[i];
				pti ++;
			}
		}
	}
	*pti = '.';
	pti++;
	for(int i=0;i<3;i++){
		if(ip_bytea2[i] != '0'){
			*pti = ip_bytea2[i];
			pti ++;
		}
		else{
			if (i==2){
				*pti = ip_bytea2[i];
				pti ++;
			}
		}
	}
	*pti = '.';
	pti++;	
	for(int i=0;i<3;i++){
		if(ip_bytea3[i] != '0'){
			*pti = ip_bytea3[i];
			pti ++;
		}
		else{
			if (i==2){
				*pti = ip_bytea3[i];
				pti ++;
			}
		}
	}
	*pti = '.';
	pti++;	
	for(int i=0;i<3;i++){
		if(ip_bytea4[i] != '0'){
			*pti = ip_bytea4[i];
			pti ++;
		}
		else{
			if (i==2){
				*pti = ip_bytea4[i];
				pti ++;
			}
		}
	}
	printf("[get server IP]:%s\n",psu -> host_ip);
	free(pkt_recv);
	close(sockfd);
	return true;
}

static bool get_service(int sockfd, struct infoset * const pinfo){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;
	int maclen = 0x6, md5len = 0x10, sendbytes = 0x21;

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
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("get service type");
			return false;
		}

	puts("[get service type]:sended out a UDP packet to auto find service type.");
	free(pkt);		
	int pkt_recv_size = 0x1000;
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
		
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[get service type]:timeout.");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[get service type]:recvice size error!");
			free(pkt_recv);
			return false;
		}
		pktDecrypt(pkt_recv, pkt_recv_size);
		memcpy(md5, pkt_recv + 2, md5len);
		memset(pkt_recv + 2, 0x0, md5len);
		
		char * ppkt_s = pkt_recv;
		ppkt_s += 0x12;
		if ( * ppkt_s == 0xa && pkt_recv[1] - 20 > 0 ) {
			++ppkt_s;
			psu -> service = (char *)calloc(*ppkt_s - 1, sizeof(char));
			strncpy(psu -> service, ppkt_s + 1, (*ppkt_s) -2 );
			printf("[get service type]:%s\n",psu -> service);
		}
		else if(* ppkt_s == 0xa){
			++ppkt_s;
			psu -> service = (char *)calloc(*ppkt_s - 1, sizeof(char));
			puts("[get service type]:service length error,please input service type:");
			scanf("%s",psu ->service);
			}
		else{
			puts("[get service type]:get service type error,exited.");
			return false;
		}		
		free(pkt_recv);
		return true;
	}
	
}

static bool try_login(int sockfd, struct infoset * const pinfo){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;
	
	int iplen = strlen(psu -> local_ip), usrlen = strlen(psu -> usr), pwdlen = strlen(psu -> pw), serlen = strlen(psu -> service), md5len = 0x10, maclen = 0x06;
	int sendbytes = 44 + iplen + usrlen + pwdlen + serlen;

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
	pktEncrypt(pkt, pkt[1]);
	
	if (sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("login");
			exit(1);
		}
	puts("[login]:sended out a UDP packet to login.");
	free(pkt);
	
	int pkt_recv_size = 0x1000;	//max recvice packet size
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[login]:timeout.");
		puts("[login]:retrying...");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[login]:recvice size error!");
			puts("[login]:retrying...");
			free(pkt_recv);
			return false;
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);

	bool login_status = (bool)pkt_recv[0x14];
	if (login_status){
		char * ppkt_s = pkt_recv;
		ppkt_s += 0x15;
		if ( *ppkt_s == 0x8 ) {
			++ ppkt_s;
			psu -> session = (char *)calloc(*ppkt_s + 1, sizeof(char));
			strncpy(psu -> session, ppkt_s + 1, *ppkt_s);
			//printf("[atclient]:Session -> %s\n",psu -> session);
		}
		free(pkt_recv);
		puts("[login]:success!");
		return login_status;
		}
	else{
		puts("[login]:failed.\n[reason]:server rejected,retrying...");
		free(pkt_recv);
		return login_status;
	}
}

static bool try_breathe(int sockfd, struct infoset * const pinfo ,unsigned int index){
	char md5[0x10] = {0x0}, *pkt, *ppkt;
	struct usrinfoSet *psu = pinfo -> psu;	
	int iplen = strlen(psu -> local_ip),sessionlen = strlen(psu -> session), md5len = 0x10, maclen = 0x06, sendbytes = 88 + sessionlen;	
	
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
	*ppkt++ = index >> 24;
	*ppkt++ = index << 8 >> 24;
	*ppkt++ = index << 16 >> 24;
	*ppkt++ = index << 24 >> 24;

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

	ComputeHash((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);	//md5
	pktEncrypt(pkt, pkt[1]);
	
	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> pss), sizeof (struct sockaddr)) == -1 ) {
			perror("keep online");
			exit(1);
		}
	puts("[keep online]:send a UDP packet to keep online.");
	free(pkt);
	
	int pkt_recv_size = 0x1000;	//max recvice packet size
	char * const pkt_recv = (char *)calloc(pkt_recv_size, sizeof(char));
	socklen_t addrlen = sizeof(struct sockaddr);
	
	int recvsize = recvfrom(sockfd, pkt_recv, pkt_recv_size, 0, (struct sockaddr *)(pinfo -> pss), &addrlen);
	if ( recvsize < 0x0 )
	{
		puts("[keep online]:timeout.");
		puts("[keep online]:failed,retrying...");
		free(pkt_recv);
		return false;
	}
	else 
	{
		if ( recvsize >= pkt_recv_size ) {
			pkt_recv[pkt_recv_size - 1] = 0x0;
			puts("[keep online]:recvice size error.");
			puts("[keep online]:failed,retrying...");
			free(pkt_recv);
			return false;
		}
	}
	pktDecrypt(pkt_recv, pkt_recv_size);
	memcpy(md5, pkt_recv + 2, md5len);
	memset(pkt_recv + 2, 0x0, md5len);

	bool login_status = (bool)pkt_recv[0x14];
	if (login_status){
		puts("[keep online]:success");
		free(pkt_recv);
		return login_status;
	}
	else{
		puts("[keep online]:failed.\n[reason]:server rejected,retrying...");
		free(pkt_recv);
		return login_status;
	}
}

extern int main(int argc, char *argv[]) 
{
	struct usrinfoSet usrinfo;
	struct sockaddr_in server_addr;
	struct infoset info;	//define struct
	
	info.pss = &server_addr;
	info.psu = &usrinfo;
	
	bool argv_scheck = false;
	bool argv_icheck = false;

	memset(&usrinfo, 0x0, sizeof(struct usrinfoSet));	//clear
	check_arg(argc, argv, &info, &argv_scheck, &argv_icheck);
	ip_mac_init(&info);
	while(1){
		if(!argv_icheck){
			bool search_server_status = get_server(&info);
			if(!search_server_status){
				exit(1);
				}
		}
		int sockfd = socket_init(&info);
		if(!argv_scheck){
		bool search_service_status = get_service(sockfd, &info);
			if(!search_service_status){
				exit(1);
			}
		}
		bool login_status = try_login(sockfd, &info);
		while (!login_status){
			sleep(5);
			login_status = try_login(sockfd, &info);
		}
		unsigned int index = 0x1000000;
		bool breath_status = try_breathe(sockfd, &info, index);
		while (breath_status){
			index += 3;
			if(index == 0xFFFFFFFF){
				index = 0x1000000;
			}
			sleep(20);
			breath_status = try_breathe(sockfd, &info, index);
		}
		close(sockfd);
		}
}