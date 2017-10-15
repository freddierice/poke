#ifndef __POKE_H__
#define __POKE_H__
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <inttypes.h>

// poke packet structure 
struct poke_packet {
	uint16_t p_version;
	uint8_t  p_address[4];
} __attribute__((packed));

// poke protocol
#define ETH_P_POKE  0x88FF
#define POKE_LEN    (sizeof(struct ethhdr) + sizeof(struct poke_packet))

// filter out ETH_P_DISC
extern struct sock_filter poke_filter_code[];
extern struct sock_fprog poke_filter_bpf;

/**
 * poke_socket creates a socket that filters out poke packets.
 *
 * Returns a file descriptor, or -1 on error.
 */
int poke_socket();

/**
 * poke_announce sends an announcement over an open poke_socket through 
 * iface_name to dst.
 *
 * Returns 0 on success, -1 on error.
 */
int poke_query(int sockfd, const char *iface_name, const char *dst);

/**
 * poke_announce sends an announcement over an open poke_socket through 
 * iface_name to dst.
 *
 * Returns 0 on success, -1 on error.
 */
int poke_announce(int sockfd, const char *iface_name, const char to[ETH_ALEN]);

/**
 * poke_recv reads a packet from the poke_packet.
 *
 * Returns 0 on sucess, -1 on error.
 */
int poke_recv(int sockfd, char from[ETH_ALEN], struct poke_packet *packet);

#endif /* __POKE_H__ */
