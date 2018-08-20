#ifndef _RAWSOCKET_H_
#define _RAWSOCKET_H_

#include <stdio.h>
#include <stdbool.h>
#include <WinSock2.h>
#include <mstcpip.h>

#include "def.h"
#include "decoder.h"

SOCKET rawsock_init();
void rawsock_bind(SOCKET s, int iid);

#endif