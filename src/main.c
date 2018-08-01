/*
TODO:
	Add checksum calculation
	Add protocol filtering DONE
	Add '--sequence' and '--no-timestamp' functionality
*/
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <getopt.h>

#include <WinSock2.h>
#include <Windows.h>

#include "rawsocket.h"
#include "utils.h"
#include "decoder.h"

#pragma comment(lib, "Ws2_32.lib")

// Global socket.
SOCKET s;

bool __stdcall handler(unsigned int signal) {
	switch (signal) {
	case CTRL_C_EVENT:
		//printf("\n");
		printf("%lld packets captured.\n", __packets_processed);
		printf("%lld packets dropped.\n", __packets_filtered);
		WSACleanup();
		closesocket(s);
		exit(0);
		break;
	case CTRL_BREAK_EVENT:
		printf("%lld packets captured.\n", __packets_processed);
		printf("%lld packets dropped.\n", __packets_filtered);
		break;
	}
	return true;
}
int main(int argc, char **argv) {
	if (argc == 1) {
		int len = strlen(argv[0]) + 8;
		printf("TCPSniff by Marin Bizov\n");

		printf("Usage: %s [-cdDilpsSt] [--count <count>]\n", argv[0]);
		buf(len, ' ');
		printf("[--dump] [--dont-verify]\n");
		buf(len, ' ');
		printf("[--interface <id>] [--list]\n");
		buf(len, ' ');
		printf("[--protocol <protocol>] [--sequence]\n");
		buf(len, ' ');
		printf("[--size <size>] [--no-timestamp]\n");

		return 0;
	}
	struct option opts[] = {
		{ "count", required_argument, 0, 'c' },
		{ "dump", no_argument, 0, 'd' },
		{ "dont-verify", no_argument, 0, 'D' },
		{ "interface", required_argument, 0, 'i' },
		{ "list", no_argument, 0, 'l' },
		{ "protocol", required_argument, 0, 'p' },
		{ "sequence", no_argument, 0, 's' },
		{ "size", required_argument, 0, 'S' },
		{ "no-timestamp", no_argument, 0, 't' }
	};
	int i;

	// Flags
	long long max_count = -1;
	bool dump = false;
	bool dont_verify = false;
	int interface_id = 0;
	bool show_seq = false;
	int max_size = PACKET_MAX;
	bool show_tcp = true;
	bool show_udp = true;
	bool show_icmp = true;
	bool no_timestamp = false;
	char *protocol = "";

	while ((i = getopt_long(argc, argv, "c:dDi:lp:sS:t", opts, 0)) != -1)
		switch (i) {
		case 'c':
			max_count = atoll(optarg);
			break;
		case 'd':
			dump = true;
			break;
		case 'D':
			dont_verify = true;
			break;
		case 'i':
			interface_id = atoi(optarg);
			break;
		case 'l':
			rawsock_init();
			list_interface();
			WSACleanup();
			return 0;
		case 'p':
			strcpy(protocol, optarg);
			strlwr(protocol);
			if (strcmp(protocol, "tcp") == 0) {
				show_tcp = true;
				show_udp = false;
				show_icmp = false;
			}
			else if (strcmp(protocol, "udp") == 0) {
				show_tcp = false;
				show_udp = true;
				show_icmp = false;
			}
			else if (strcmp(protocol, "icmp") == 0) {
				show_tcp = false;
				show_udp = false;
				show_icmp = true;
			}
			break;
		case 's':
			show_seq = true;
			break;
		case 'S':
			max_size = atoi(optarg);
			break;
		case 't':
			no_timestamp = true;
			break;
		case '?':
			return 1;
		default:
			return 0;
		}
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)handler, true);

	__packets_processed = 0;
	__packets_filtered = 0;
	__dump = dump;
	__show_tcp = show_tcp;
	__show_udp = show_udp;
	__show_icmp = show_icmp;

	long long cnt = 0;
	char *packet = (char*)malloc(max_size);
	int size;

	// Initialize raw socket
	s = rawsock_init();
	rawsock_bind(s, interface_id);

	while (true) {
		size = recv(s, packet, max_size, 0);

		if (size == 0) break;
		if (size > 0 && size <= max_size) {
			decode_packet(packet, size);
		}
		if (cnt == max_count) {
			//printf("Reached maximum packet count.\n");
			WSACleanup();
			closesocket(s);
			exit(0);
		}
		cnt++;
	}
	WSACleanup();
	closesocket(s);

	return 0;
}
