#include "stdio.h"
#include "string.h"

#include "poke.h"

int main(int argc, const char *argv[]) {
	
	int sockfd, num, send;
	char to[6] = "\x00\x28\xf8\x1d\xde\xc2";
	if (argc != 2) {
		fprintf(stderr, "need to send or recv\n");
		return 1;
	}

	if (!strcmp(argv[1], "send")) {
		send = 1;
	}else if (!strcmp(argv[1], "recv")) {
		send = 0;
	}else{
		fprintf(stderr, "need to send or recv\n");
		return 1;
	}
	
	if ((sockfd = poke_socket()) < 0)
		return 1;

	if (send) {
		if (poke_announce(sockfd, "wlp59s0", to) == -1)
			fprintf(stderr, "could not send announce\n");
	}else{
		while (1) {
			struct poke_packet p;
			unsigned char from[ETH_ALEN];
			poke_recv(sockfd, from, &p);
			printf("type: %u, %02x:%02x:%02x:%02x:%02x:%02x at %u.%u.%u.%u\n", 
					p.p_version, from[0], from[1], from[2], from[3], from[4], 
					from[5], p.p_address[0], p.p_address[1], p.p_address[2], 
					p.p_address[3]);
		}
	}

	return 0;
}
