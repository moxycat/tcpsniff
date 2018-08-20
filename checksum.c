#include "checksum.h"

// Calculate tcp checksum
unsigned short tcp_checksum(unsigned short len, unsigned short *src_ip, unsigned short *dst_ip, char *packet) {
	long cksum = 0;

	if ((len % 2) == 1) {
		//packet[len] = 0x0;
		len++;
	}

	cksum += ntohs(src_ip[0]);
	cksum += ntohs(src_ip[1]);
	cksum += ntohs(dst_ip[0]);
	cksum += ntohs(dst_ip[1]);
	cksum += len;
	cksum += 6; // TCP protocol id

	for (int i = 0; i < (len / 2); i++) {
		cksum += ntohs(packet[i]);
	}

	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum += (cksum >> 16);

	cksum = ~cksum;

	return htons((unsigned short)cksum);
}