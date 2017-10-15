#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <errno.h>

#include "poke.h"

struct sock_filter poke_filter_code[] = {
    { 0x28,  0,  0, 0x0000000c },
    { 0x15,  0,  1, 0x000088ff },
    { 0x06,  0,  0, 0xffffffff },
    { 0x06,  0,  0, 0000000000 },
};                               

struct sock_fprog poke_filter_bpf = {
    .len = sizeof(poke_filter_code)/sizeof(struct sock_filter),
    .filter = poke_filter_code,  
};  

int iface2info(const char *iface_name, int *iface, void *hw_addr, void *inet_addr);
void print_packet(int sockfd);

int poke_socket() {
	int sockfd;
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("could not create socket");
		return -1;
	}

	// add the filter
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &poke_filter_bpf, 
				sizeof(poke_filter_bpf)) < 0) {
		perror("could not set filter");
		return -1;
	}

	return sockfd;
}

int poke_announce(int sockfd, const char *iface_name, const char to[ETH_ALEN]) {
	
	int iface;
	unsigned char buf[POKE_LEN], ip[4];
	struct ethhdr *hdr;
	struct poke_packet *poke;

	struct sockaddr_ll socket_addr = {
		.sll_family = PF_PACKET,
		.sll_protocol = htons(ETH_P_POKE),
		.sll_pkttype = PACKET_OUTGOING,
		.sll_halen = ETH_ALEN,
	};
	
	if (iface2info(iface_name, &iface, socket_addr.sll_addr, ip) == -1)
		return sockfd;
	socket_addr.sll_ifindex = iface;

	hdr = (struct ethhdr *)buf;
	memcpy(hdr->h_dest, to, ETH_ALEN);
	memcpy(hdr->h_source, socket_addr.sll_addr, ETH_ALEN);
	hdr->h_proto = htons(ETH_P_POKE);
	
	poke = (struct poke_packet *)(buf + sizeof(struct ethhdr));
	poke->p_version = 0;
	memcpy(poke->p_address, ip, 4);
	
	if (sendto(sockfd, buf, POKE_LEN, 0, (const struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0) 
		perror("could not send");
	return 0;
}

int poke_recv(int sockfd, char from[ETH_ALEN], struct poke_packet *packet) {
	int num;
	struct ethhdr *hdr;
	char buf[POKE_LEN];

	while (1) {
		struct sockaddr_ll addr;
		socklen_t addr_len = sizeof(struct sockaddr_ll);
		if ((num = recvfrom(sockfd, buf, POKE_LEN, 0, (struct sockaddr *)&addr,
						&addr_len)) == -1) {
			perror("could not recv packet");
			return -1;
		}

		if (addr.sll_pkttype != PACKET_OUTGOING) 
			break;
	}
	memcpy(from, ((struct ethhdr *)buf)->h_source, ETH_ALEN);
	memcpy(packet, buf + sizeof(struct ethhdr), sizeof(struct poke_packet));
	return 0;
}

int iface2info(const char *iface_name, int *iface, void *hw_addr, void *inet_addr) {
	int sockfd;
	struct ifreq ifr;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("could not create socket");
		return -1;
	}

	memset((void *)&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
		perror("could not get index");
		return -1;
	}
	*iface = ifr.ifr_ifindex;

	memset((void *)&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("could not get hwaddr");
		return -1;
	}
	memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(sockfd);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("could not create socket");
		return -1;
	}

	memset((void *)&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		perror("could not get hwaddr");
		return -1;
	}
	close(sockfd);
	
	memcpy(inet_addr, ifr.ifr_addr.sa_data+2, 4);
}
