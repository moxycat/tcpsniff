#include "decoder.h"

void decode_tcp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	tcp_header_t *tcp = (tcp_header_t*)(packet + (ip->hl * 4));
	unsigned char flags = (ntohs(tcp->ctrlbits) & 0x003f);

	printf("%s -> %s TCP %u %d -> %d Seq=%u Ack=%u [",
		iptostr(ip->src_ip), iptostr(ip->dst_ip),
		len,
		ntohs(tcp->src_port), ntohs(tcp->dst_port),
		ntohl(tcp->seq), ntohl(tcp->ackno)
	);
	
	if (flags & 0x01) printf("FIN ");
	if (flags & 0x02) printf("SYN ");
	if (flags & 0x04) printf("RST ");
	if (flags & 0x08) printf("PSH ");
	if (flags & 0x10) printf("ACK ");
	if (flags & 0x20) printf("URG ");

	printf("\b] Window=%u\n", ntohs(tcp->window));

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));

	return;
}
void decode_udp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	udp_header_t *udp = (udp_header_t*)(packet + (ip->hl * 4));

	printf("%s -> %s UDP %u %d -> %d Len=%d Checksum=%d\n",
		iptostr(ip->src_ip), iptostr(ip->dst_ip),
		len,
		ntohs(udp->src_port), ntohs(udp->dst_port),
		ntohs(udp->len),
		ntohs(udp->cksum)
	);

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));

	return;
}
void decode_icmp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	icmp_header_t *icmp = (icmp_header_t*)(packet + (ip->hl * 4));

	printf("%s -> %s ICMP %u Type=%d(",
		iptostr(ip->src_ip), iptostr(ip->dst_ip),
		len,
		(unsigned int)icmp->type
		);

	switch (icmp->type) {
	case 0:
		printf("Echo reply");
		break;
	case 3:
		printf("Destination unreachable");
		break;
	case 4:
		printf("Source quench");
		break;
	case 5:
		printf("Redirect message");
		break;
	case 8:
		printf("Echo request");
		break;
	}
	printf(") Code=%d Id=%u Seq=%u\n",
		(unsigned int)icmp->code,
		ntohs(icmp->id),
		ntohs(icmp->seq)
	);

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));

	return;
}

void decode_packet(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;

	switch (ip->proto) {
	case IPPROTO_TCP:
		if (__show_tcp) {
			decode_tcp(packet, len);
			__packets_processed++;
		}
		else __packets_filtered++;
		break;
	case IPPROTO_UDP:
		if (__show_udp) {
			decode_udp(packet, len);
			__packets_processed++;
		}
		else __packets_filtered++;
		break;
	case IPPROTO_ICMP:
		if (__show_icmp) {
			decode_icmp(packet, len);
			__packets_processed++;
		}
		else __packets_filtered++;
		break;
	case IPPROTO_IGMP:
		break;
	default:
		printf("%s -> %s UNK Protocol=%d\n",
			iptostr(ip->src_ip), iptostr(ip->dst_ip), (unsigned int)ip->proto);
		break;
	}
	return;
}