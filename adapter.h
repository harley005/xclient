#ifndef __ADAPTER_H__
#define __ADAPTER_H__

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

typedef struct _ADAPTER
{
	int 	sockfd;
	int 	index;
	char 	ip[4];
	char 	mac[6];
	struct 	sockaddr_ll addr;
} ADAPTER;

ADAPTER *adapter_open(char *adapter_name);
void adapter_release(ADAPTER *adapter);
void adapter_set_timeout(ADAPTER *adapter, int second);
int adapter_send_packet(ADAPTER *adapter, const char *data, int len);
int adapter_send_broadcast_packet(ADAPTER *adapter, const char *data, int len);
int adapter_send_multicast_packet(ADAPTER *adapter, const char *data, int len);
int adapter_get_packet(ADAPTER *adapter, char *data, int len);

#endif
