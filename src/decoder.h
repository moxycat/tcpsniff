#ifndef _DECODER_H_
#define _DECODER_H_

#include <stdio.h>
#include <stdbool.h>
#include <WinSock2.h>

#include "protocol.h"
#include "utils.h"
#include "checksum.h"

long long __packets_processed, __packets_filtered;
bool __dump;

bool __show_tcp, __show_udp, __show_icmp;

void decode_packet(char *packet, unsigned int len);

#endif