#include "decoder.h"

void decode_tcp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	tcp_header_t *tcp = (tcp_header_t*)(packet + (ip->hl * 4));
	unsigned char flags = (ntohs(tcp->ctrlbits) & 0x003f);

	if ((__no_timestamp == false) && (__verbose == false)) printf("%s ", get_time());

	if (__resolve) {
		printf("TCP %s:%d -> %s:%d",
			resolve_ip(ip->src_ip), ntohs(tcp->src_port),
			resolve_ip(ip->dst_ip), ntohs(tcp->dst_port)
		);
	}
	else {
		printf("TCP %s:%d -> %s:%d",
			iptostr(ip->src_ip), ntohs(tcp->src_port),
			iptostr(ip->dst_ip), ntohs(tcp->dst_port)
		);
	}

	if (!__quiet) {
		printf("  flags [");

		if (flags & 0x01) printf("fin,");
		if (flags & 0x02) printf("syn,");
		if (flags & 0x04) printf("rst,");
		if (flags & 0x08) printf("psh,");
		if (flags & 0x10) printf("ack,");
		if (flags & 0x20) printf("urg,");

		printf("\b] seq %u, ack %u, win %u, cksum 0x%x, length %u\n",
			ntohl(tcp->seq), ntohl(tcp->ackno), ntohs(tcp->window), ntohs(tcp->cksum), len
		);
	}
	else printf("\n");

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));
	else if (__dump_full) write_ascii(packet, len);

	return;
}
void decode_udp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	udp_header_t *udp = (udp_header_t*)(packet + (ip->hl * 4));

	if ((__no_timestamp == false) && (__verbose == false)) printf("%s ", get_time());

	if (__resolve) {
		printf("UDP %s:%d -> %s:%d",
			resolve_ip(ip->src_ip), ntohs(udp->src_port),
			resolve_ip(ip->dst_ip), ntohs(udp->dst_port)
		);
	}
	else {
		printf("UDP %s:%d -> %s:%d",
			iptostr(ip->src_ip), ntohs(udp->src_port),
			iptostr(ip->dst_ip), ntohs(udp->dst_port)
		);
	}

	if (!__quiet) {
		printf("  cksum 0x%x, length %u\n",
			ntohs(udp->cksum),
			len
		);
	}
	else printf("\n");

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));
	else if (__dump_full) write_ascii(packet, len);

	return;
}
void decode_icmp(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;
	icmp_header_t *icmp = (icmp_header_t*)(packet + (ip->hl * 4));

	if ((__no_timestamp == false) && (__verbose == false)) printf("%s ", get_time());

	if (__resolve) {
		printf("ICMP %s -> %s",
			resolve_ip(ip->src_ip), resolve_ip(ip->dst_ip)
		);
	}
	else {
		printf("ICMP %s -> %s",
			iptostr(ip->src_ip), iptostr(ip->dst_ip)
		);
	}

	if (!__quiet) {
		printf("  type ");

		switch (icmp->type) {
		case 0:
			printf("echo reply");
			break;
		case 3:
			printf("destination unreachable");
			break;
		case 4:
			printf("source quench");
			break;
		case 5:
			printf("redirect message");
			break;
		case 8:
			printf("echo request");
			break;
		}
		printf(" (%d), code %d, id %u, seq %u, length %u\n",
			(unsigned int)icmp->type,
			(unsigned int)icmp->code,
			ntohs(icmp->id),
			ntohs(icmp->seq),
			len
		);
	}
	else printf("\n");

	if (__dump) write_ascii(packet + (ip->hl * 4), len - (ip->hl * 4));
	else if (__dump_full) write_ascii(packet, len);

	return;
}

void decode_packet(char *packet, unsigned int len) {
	ip_header_t *ip = (ip_header_t*)packet;

	if (__verbose) {
			switch (ip->proto) {
			case IPPROTO_TCP:
				if (!__no_timestamp) printf("%s ", get_time());
				if (__show_tcp) {
					printf("IP tos 0x%x, id %u, ttl %u, proto ",
						(unsigned int)ip->tos, ntohs(ip->id), (unsigned int)ip->ttl);
					switch (ip->proto) {
					case IPPROTO_ICMP:
						printf("ICMP (1)"); break;
					case IPPROTO_IGMP:
						printf("IGMP (2)"); break;
					case IPPROTO_GGP:
						printf("GGP (3)"); break;
					case IPPROTO_TCP:
						printf("TCP (6)"); break;
					case IPPROTO_CBT:
						printf("CBT (7)"); break;
					case IPPROTO_EGP:
						printf("EGP (8)"); break;
					case IPPROTO_IGP:
						printf("IGP (9)"); break;
					case IPPROTO_PUP:
						printf("PUP (12)"); break;
					case IPPROTO_UDP:
						printf("UDP (17)"); break;
					default:
						printf("??? (%u)", (unsigned int)ip->proto); break;
					}
					printf(", cksum 0x%x\n    ", ntohs(ip->cksum));
				}
				break;
			case IPPROTO_UDP:
				if (!__no_timestamp) printf("%s ", get_time());
				if (__show_udp) {
					printf("IP tos 0x%x, id %d, ttl %u, proto ",
						(unsigned int)ip->tos, ntohs(ip->id), (unsigned int)ip->ttl);
					switch (ip->proto) {
					case IPPROTO_ICMP:
						printf("ICMP (1)"); break;
					case IPPROTO_IGMP:
						printf("IGMP (2)"); break;
					case IPPROTO_GGP:
						printf("GGP (3)"); break;
					case IPPROTO_TCP:
						printf("TCP (6)"); break;
					case IPPROTO_CBT:
						printf("CBT (7)"); break;
					case IPPROTO_EGP:
						printf("EGP (8)"); break;
					case IPPROTO_IGP:
						printf("IGP (9)"); break;
					case IPPROTO_PUP:
						printf("PUP (12)"); break;
					case IPPROTO_UDP:
						printf("UDP (17)"); break;
					default:
						printf("??? (%u)", (unsigned int)ip->proto); break;
					}
					printf(", cksum 0x%x\n    ", ntohs(ip->cksum));
				}
				break;
			case IPPROTO_ICMP:
				if (!__no_timestamp) printf("%s ", get_time());
				if (__show_icmp) {
					printf("IP tos 0x%x, id %d, ttl %u, proto ",
						(unsigned int)ip->tos, ntohs(ip->id), (unsigned int)ip->ttl);
					switch (ip->proto) {
					case IPPROTO_ICMP:
						printf("ICMP (1)"); break;
					case IPPROTO_IGMP:
						printf("IGMP (2)"); break;
					case IPPROTO_GGP:
						printf("GGP (3)"); break;
					case IPPROTO_TCP:
						printf("TCP (6)"); break;
					case IPPROTO_CBT:
						printf("CBT (7)"); break;
					case IPPROTO_EGP:
						printf("EGP (8)"); break;
					case IPPROTO_IGP:
						printf("IGP (9)"); break;
					case IPPROTO_PUP:
						printf("PUP (12)"); break;
					case IPPROTO_UDP:
						printf("UDP (17)"); break;
					default:
						printf("??? (%u)", (unsigned int)ip->proto); break;
					}
					printf(", cksum 0x%x\n    ", ntohs(ip->cksum));
				}
				break;
			default:
				if (!__no_timestamp) printf("%s ", get_time());
				printf("IP tos 0x%x, id %d, ttl %u, proto ",
					(unsigned int)ip->tos, ntohs(ip->id), (unsigned int)ip->ttl);
				switch (ip->proto) {
				case IPPROTO_ICMP:
					printf("ICMP (1)"); break;
				case IPPROTO_IGMP:
					printf("IGMP (2)"); break;
				case IPPROTO_GGP:
					printf("GGP (3)"); break;
				case IPPROTO_TCP:
					printf("TCP (6)"); break;
				case IPPROTO_CBT:
					printf("CBT (7)"); break;
				case IPPROTO_EGP:
					printf("EGP (8)"); break;
				case IPPROTO_IGP:
					printf("IGP (9)"); break;
				case IPPROTO_PUP:
					printf("PUP (12)"); break;
				case IPPROTO_UDP:
					printf("UDP (17)"); break;
				default:
					printf("??? (%u)", (unsigned int)ip->proto); break;
				}
				printf(", cksum 0x%x\n    ", ntohs(ip->cksum));
				break;
			}
	}

	switch (ip->proto) {
	case IPPROTO_TCP:
		if (__show_tcp) {
			decode_tcp(packet, len);
			__packets_processed++;
		}
		else
			__packets_filtered++;
		break;
	case IPPROTO_UDP:
		if (__show_udp) {
			decode_udp(packet, len);
			__packets_processed++;
		}
		else
			__packets_filtered++;
		break;
	case IPPROTO_ICMP:
		if (__show_icmp) {
			decode_icmp(packet, len);
			__packets_processed++;
		}
		else
			__packets_filtered++;
		break;
	default:
		if (__show_warnings) {
			if ((__no_timestamp == false) && (__verbose == false)) printf("%s ", get_time());
			printf("WARN %s -> %s  Protocol decoder not implemented\n", iptostr(ip->src_ip), iptostr(ip->dst_ip));
			__packets_processed++;
		}
		else __packets_filtered++;
		break;
	}
	return;
}