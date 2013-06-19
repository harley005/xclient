#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <assert.h>
#include "adapter.h"

#define ETH_P_EAP		0x888e

const char Nearest[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
const char Broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

ADAPTER *adapter_open(char *adapter_name)
{
	ADAPTER *adapter = (ADAPTER *)malloc(sizeof(ADAPTER));
	assert(adapter != NULL);
	memset(adapter, 0, sizeof(ADAPTER));
	adapter->sockfd = socket(AF_PACKET, SOCK_DGRAM, 0);
	if (adapter->sockfd < 0) {
		perror("socket");
		goto failed;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, adapter_name, IFNAMSIZ);
	if (ioctl(adapter->sockfd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		goto failed;
	}
	adapter->index = ifr.ifr_ifindex;

	if (ioctl(adapter->sockfd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl");	
		goto failed;
	}
	memcpy(adapter->ip, ifr.ifr_addr.sa_data+2, 4);
	
	if (ioctl(adapter->sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		goto failed;
	}
	memcpy(adapter->mac, (char *)&ifr.ifr_hwaddr+2, 6);

	int on = 1;
	if (setsockopt(adapter->sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		goto failed;
	}

	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = adapter->index;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = sizeof(Nearest);
	memcpy(mr.mr_address, Nearest, sizeof(Nearest));
	if (setsockopt(adapter->sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		perror("setsockopt");
		goto failed;
	}

	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_EAP);
	addr.sll_ifindex = adapter->index;
	if (bind(adapter->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		goto failed;
	}

	return adapter;
failed:
	close(adapter->sockfd);
	free(adapter);
	return NULL;
}

void adapter_release(ADAPTER *adapter)
{
	close(adapter->sockfd);
	free(adapter);
}

void adapter_set_timeout(ADAPTER *adapter, int second)
{
	struct timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = second;
	if (setsockopt(adapter->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		perror("setsockopt");
}

static int send_packet(ADAPTER *adapter, struct sockaddr_ll *addr, const char *data, int len)
{
	char buf[46] = {0};
	if (len < 46) {
		memcpy(buf, data, len);
		return sendto(adapter->sockfd, buf, 46, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_ll));
	}
	return sendto(adapter->sockfd, data, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_ll));
}

int adapter_send_packet(ADAPTER *adapter, const char *data, int len)
{
	return send_packet(adapter, &adapter->addr, data, len);
}

int adapter_send_broadcast_packet(ADAPTER *adapter, const char *data, int len)
{
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_EAP);
	addr.sll_ifindex = adapter->index;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, Broadcast, sizeof(Broadcast));
	return send_packet(adapter, &addr, data, len);
}

int adapter_send_multicast_packet(ADAPTER *adapter, const char *data, int len)
{
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_EAP);
	addr.sll_ifindex = adapter->index;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, Nearest, sizeof(Nearest));
	return send_packet(adapter, &addr, data, len);
}

int adapter_get_packet(ADAPTER *adapter, char *data, int len)
{
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	return recvfrom(adapter->sockfd, data, len, 0, (struct sockaddr *)&adapter->addr, &addr_len);
}
