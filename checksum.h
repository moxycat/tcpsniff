#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#include <WinSock2.h>

unsigned short tcp_checksum(unsigned short len, unsigned short *src_ip, unsigned short *dst_ip, char *packet);

#endif