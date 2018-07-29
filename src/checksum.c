#include "checksum.h"

unsigned short checksum(char *data, int size) {
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *data++;
		size -= sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned char*)data;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}