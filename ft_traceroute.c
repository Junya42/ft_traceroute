#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
 
#define PACKET_SIZE 64
 
struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
};
 
struct ipheader {
	unsigned char ihl:4,
				  version:4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};
 
unsigned short checksum(void *b, int len) {
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;
 
	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
 
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
 
	return result;
}
 
int main(int ac, char **av) {
 
	if (ac < 2) {
		fprintf(stderr, "Usage: %s <destination\n", av[0]);
		return 1;
	}
 
	struct addrinfo hints = {0}, *res;
 
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;
 
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		perror("Socket creation failure");
		return 1;
	}
 
	const char *target = av[1];
	if (getaddrinfo(target, NULL, &hints, &res) != 0) {
		fprintf(stderr, "ft_traceroute: unknown host\n");
		close(sockfd);
		return 1;
	}
 
	struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
 
	int seq = 0;
	char packet[64];
 
	struct icmphdr *icmp = (struct icmphdr *)packet;
 
	icmp->type = 8;
	icmp->code = 0;
	icmp->id = htons(getpid());
	icmp->checksum = 0;
 
	while (1) {
 
		icmp->seq = htons(++seq);
		icmp->checksum = 0;
		gettimeofday((struct timeval *)(packet + 8), NULL);
 
		icmp->checksum = checksum(packet, PACKET_SIZE);
 
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &seq, sizeof(seq));
		sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
 
 
		char recv_buf[PACKET_SIZE];
		struct iovec iov[1];
		iov[0].iov_base = recv_buf;
		iov[0].iov_len = sizeof(recv_buf);
		struct sockaddr_in sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);
		struct msghdr msg = {0};
		msg.msg_name = &sender_addr;
		msg.msg_namelen = sender_addr_len;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
 
		int recv_len = recvmsg(sockfd, &msg, 0);
 
		printf("%d bytes from %s: icmp_seq=%d\n", recv_len, inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq));
 
		sleep(1);
	}
	freeaddrinfo(res);
	close(sockfd);
	return 0;
}
