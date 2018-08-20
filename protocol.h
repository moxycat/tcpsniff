#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

// ip header
typedef struct ip_header_s {
	unsigned char hl : 4; // header length
	unsigned char ver : 4; // version
	unsigned char tos; // type of service
	unsigned short totlen; // total packet length
	unsigned short id; // unique identifier
	unsigned short flags; // flags
	unsigned char ttl; // time to live
	unsigned char proto; // protocol
	unsigned short cksum; // ip checksum
	unsigned int src_ip; // source ip address
	unsigned int dst_ip; // destination ip address
} ip_header_t;

// tcp header
typedef struct tcp_header_s {
	unsigned short src_port; // source port
	unsigned short dst_port; // destination port
	unsigned int seq; // sequence number
	unsigned int ackno; // acknowledgment number
	unsigned short ctrlbits; // control bits
	unsigned short window; // window size
	unsigned short cksum; // tcp checksum
	unsigned short urgptr; // urgent pointer
} tcp_header_t;

// udp header
typedef struct udp_header_s {
	unsigned short src_port; // source port
	unsigned short dst_port; // destination port
	unsigned short len; // packet length
	unsigned short cksum; // udp checksum
} udp_header_t;

// icmp header
typedef struct icmp_header_s {
	unsigned char type; // error type
	unsigned char code; // sub code
	unsigned short cksum; // checksum
	unsigned short id; // identifier
	unsigned short seq; // sequence number
} icmp_header_t;

// igmp header
typedef struct igmp_header_s {
	unsigned char type;

} igmp_header_t;

#endif