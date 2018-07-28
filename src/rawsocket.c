#include "rawsocket.h"

SOCKET rawsock_init() {
	WSADATA wsa;
	SOCKET s;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printf("Error: failed to start WinSock2.\n");
		exit(-1);
	}
	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (s == INVALID_SOCKET) {
		printf("Error: failed to initialize socket.\n");
		exit(-1);
	}
	return s;
}

void rawsock_bind(SOCKET s, int iid) {
	SOCKADDR_IN addr;
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
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	memcpy(&addr.sin_addr.S_un.S_addr, h->h_addr_list[iid], h->h_length);
	if (bind(s, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("Error: failed to bind socket.\n");
		exit(-1);
	}
	unsigned int junk;
	int code = RCVALL_ON;
	if (WSAIoctl(s, SIO_RCVALL, &code, sizeof(code), NULL, 0, &junk, NULL, NULL) == SOCKET_ERROR) {
		printf("Error: failed to set promiscuous mode on socket.\n");
		exit(-1);
	}
	printf("Listening on %s ...\n", inet_ntoa(addr.sin_addr));
	return;
	
}