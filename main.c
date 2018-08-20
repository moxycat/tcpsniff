/*
	tcpsniff -- network packet sniffer.
	Written by Marin Bizov

	Started work on 25 July 2018
*/
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

#include <WinSock2.h>
#include <Windows.h>

#include "def.h"
#include "getopt.h"
#include "rawsocket.h"
#include "decoder.h"

#pragma comment(lib, "Ws2_32.lib")

/*
TODO:
	Add filter parser.
	In decoder.c change len variable in output to ip->totlen / 256
*/

// Global socket.
SOCKET s;

// Output file
FILE *wfp;
bool write;

// Input file
FILE *rfp;
bool read;

bool __stdcall handler(unsigned int signal) {
	switch (signal) {
	case CTRL_C_EVENT:
		//printf("\n");
		printf("%lld packets captured.\n", __packets_processed);
		printf("%lld packets dropped.\n", __packets_filtered);
		WSACleanup();
		closesocket(s);
		if (read)
			fclose(rfp);
		if (write)
			fclose(wfp);
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
		printf("tcpsniff by Marin Bizov\n");
		printf("Usage: %s [-cdDilpqstvw] [--count <count>]\n", argv[0]);
		buf(len, ' ');
		printf("[--dump] [--dump-full]\n");
		buf(len, ' ');
		printf("[--interface <id>] [--list]\n");
		buf(len, ' ');
		printf("[--protocol <protocol>] [--quiet]\n");
		buf(len, ' ');
		printf("[--size <size>] [--no-timestamp]\n");
		buf(len, ' ');
		printf("[--verbose] [--no-warning]\n");
		//buf(len, ' ');
		//printf("[--dump-hex] [--dump-full-hex]\n");
		return 0;
	}

	struct option opts[] = {
		{ "count", required_argument, 0, 'c' },
		{ "dump", no_argument, 0, 'd' },
		{ "dump-full", no_argument, 0, 'D' },
		{ "interface", required_argument, 0, 'i' },
		{ "list", no_argument, 0, 'l' },
		{ "protocol", required_argument, 0, 'p' },
		{ "quiet", no_argument, 0, 'q' },
		{ "size", required_argument, 0, 's' },
		{ "no-timestamp", no_argument, 0, 't' },
		{ "verbose", no_argument, 0, 'v' },
		{ "no-warning", no_argument, 0, 'w' },
		{ "dump-hex", no_argument, 0, 'x' },
		{ "dump-full-hex", no_argument, 0, 'X' }
	};
	int i;

	// Set reader/writer args
	write = false;
	read = false;

	// Flags
	long long max_count = -1;
	int interface_id = 0;
	int max_size = PACKET_MAX;
	char *protocol = "";


	// Sniffer arguments
	long long cnt = 1;
	int size;
	char *packet = (char*)malloc(max_size);

	// Initialize decoder variables
	__show_tcp = true;
	__show_udp = true;
	__show_icmp = true;
	__show_warnings = true;
	__dump = false;
	__dump_full = false;

	__verbose = false;
	__resolve = false;
	__quiet = false;
	__no_timestamp = false;

	// Start of argument parser
	while ((i = getopt_long(argc, argv, "c:dDi:lp:qs:tvwxX", opts, 0)) != -1) {
		switch (i) {
		case 'c':
			max_count = atoll(optarg);
			break;
		case 'd':
			__dump = true;
			break;
		case 'D':
			__dump_full = true;
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
				__show_tcp = true;
				__show_udp = false;
				__show_icmp = false;
				break;
			}
			else if (strcmp(protocol, "udp") == 0) {
				__show_tcp = false;
				__show_udp = true;
				__show_icmp = false;
				break;
			}
			else if (strcmp(protocol, "icmp") == 0) {
				__show_tcp = false;
				__show_udp = false;
				__show_icmp = true;
				break;
			}
			else {
				printf("%s: error: invaild protocol type.\n", __argv[0]);
				return 1;
			}
		case 'q':
			__quiet = true;
			__show_warnings = false;
			break;
		case 's':
			max_size = atoi(optarg);
			break;
		case 't':
			__no_timestamp = true;
			break;
		case 'v':
			__verbose = true;
			break;
		case 'w':
			__show_warnings = false;
			break;
		case 'x':
			break;
		case 'X':
			break;
		case '?':
			return 1;
		default:
			return 0;
		}
	}
	// End of argument parser

	// Reader mode
	if (read) {

	}

	// Live capture mode

	// Set packet variables to 0
	__packets_processed = 0;
	__packets_filtered = 0;
	
	// Initialize raw socket
	s = rawsock_init();
	rawsock_bind(s, interface_id);

	// Start ctrl handler
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)handler, true);

	// Start main sniffer loop
	while (true) {
		size = recv(s, packet, max_size, 0);

		if (write) {
			fwrite(packet, 1, size, wfp);
			fflush(wfp);
		}

		if (size > 0 && size <= max_size) {
			decode_packet(packet, size);
		}
		else __packets_filtered++;

		if (size == 0) break;
		if (cnt == max_count) break;
		
		cnt++;
	}

	// Stop WSA, close socket and files
	WSACleanup();
	closesocket(s);
	if (read)
		fclose(rfp);
	if (write)
		fclose(wfp);

	// Exit
	return 0;
}