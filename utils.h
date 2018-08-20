#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <WinSock2.h>

#include "def.h"

static char *resolve_ip(unsigned int addr) {
	char *hostname = (char*)malloc(HOSTNAME_MAX);
	struct hostent *h;
	h = gethostbyaddr((char*)&addr, 4, AF_INET);
	strcpy(hostname, h->h_name);
	return hostname;
}
static char *get_time() {
	time_t timer;
	char *buffer = (char*)malloc(26);
	struct tm* tm_info;
	time(&timer);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%H:%M:%S", tm_info);
	return buffer;
}

static void buf(int n, int c) {
	for (int i = 0; i < n; i++)
		putchar(c);
	return;
}
static void write_ascii(char *data, unsigned int len) {
	for (unsigned int i = 0; i < len; i++) {
		if (isprint(data[i]))
			putchar(data[i]);
		else putchar('.');
	}
	putchar('\n');
	return;
}
static char *iptostr(unsigned int ip) {
	struct sockaddr_in sock;
	memset(&sock, 0, sizeof(sock));
	sock.sin_addr.S_un.S_addr = ip;
	return inet_ntoa(sock.sin_addr);
}

static void list_interface() {
	struct in_addr addr;
	struct hostent *h;
	char hostname[HOSTNAME_MAX];
	if (gethostname(hostname, HOSTNAME_MAX) == SOCKET_ERROR) {
		printf("Error: failed to get hostname.\n");
		exit(-1);
	}

	h = gethostbyname(hostname);
	if (h == NULL) {
		printf("Error: failed to get host by name.\n");
		exit(-1);
	}

	for (int i = 0; h->h_addr_list[i] != NULL; i++) {
		memcpy(&addr, h->h_addr_list[i], sizeof(struct in_addr));
		printf("%d. %s\n", i, inet_ntoa(addr));
	}

	return;
}

#endif