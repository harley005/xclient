#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>
#include "encrypt.h"
#include "eap.h"

const char ClientVersion[] = "CH\x11V5.00-0105";
const char H3CKey[] = "Oly5D62FaE94W7";
uint8_t magic[4] = {0};

static void EORMix(char *data, const char *key, int len)
{
	char tmp[20] = {0};
	
	int n = len / strlen(key);
	
	for (int i=0; i<n; i++)
	    memcpy(tmp+i*strlen(key), key, strlen(key));

	memcpy(tmp+n*strlen(key), key, len%strlen(key));
	
	for (int i=0; i<len; i++)
	    data[i] = data[i] ^ tmp[i];

	for (int i=0; i<len; i++)
	    data[len-i-1] = data[len-i-1] ^ tmp[i];
}

static int GetEncodedVersion(char *buf)
{
	char version[20] = {0};
	char tmp[9] = {0};
	
	sprintf(tmp, "%02x%02x%02x%02x", magic[0], magic[1], magic[2], magic[3]);
	
	memcpy(version, ClientVersion, strlen(ClientVersion));
	memcpy(version+16, magic, 4);
	
	EORMix(version, tmp, 16);
	EORMix(version, H3CKey, 20);
	
	return Base64Encode(version, buf, 20);
}

EAP *eap_open(char *adapter_name, char *user, char *passwd)
{
	EAP *eap = (EAP *)malloc(sizeof(EAP));
	assert(eap != NULL);
	eap->adapter = adapter_open(adapter_name);
	if (eap->adapter == NULL)
		goto failed;

	srand(time(NULL));
	*(int *)magic = rand();

	strcpy(eap->user, user);
	strcpy(eap->passwd, passwd);
	eap->retry_times = 0;
	eap->multicast = 0;
	return eap;

failed:
	free(eap);
	return NULL;
}

void eap_release(EAP *eap)
{
	adapter_release(eap->adapter);
	free(eap);
}

void eap_send_start(EAP *eap)
{
	printf("[%ld]send: eap start\n", time(NULL));
	EAP_PACKET packet;
	memset(&packet, 0, sizeof(EAP_PACKET));
	packet.version = 1;
	packet.pkt_type = EAP_START;
	packet.len1 = 0;
	if (eap->multicast == 0)
		adapter_send_broadcast_packet(eap->adapter, (char *)&packet, sizeof(packet));
	else 
		adapter_send_multicast_packet(eap->adapter, (char *)&packet, sizeof(packet));
}

void eap_send_logoff(EAP *eap)
{
	printf("[%ld]send: eap logoff\n", time(NULL));
	EAP_PACKET packet;
	memset(&packet, 0, sizeof(EAP_PACKET));
	packet.version = 1;
	packet.pkt_type = EAP_LOGOFF;
	packet.len1 = 0;
	if (eap->multicast == 0)
		adapter_send_broadcast_packet(eap->adapter, (char *)&packet, sizeof(packet));
	else 
		adapter_send_multicast_packet(eap->adapter, (char *)&packet, sizeof(packet));}

void eap_send_identify_response(EAP *eap)
{
	printf("[%ld]send: eap identify response\n", time(NULL));
	char buf[128] = {0};
	EAP_PACKET *packet = (EAP_PACKET *)buf;

	packet->version = 1;
	packet->pkt_type = EAP_EAP;
	packet->code = EAP_RESPONSE;
	packet->id = eap->id;
	packet->eap_type = EAP_IDENTIFY;

	IDENTIFY_FRM *identify = (IDENTIFY_FRM *)packet->payload;
	
	identify->type_ip = htons(IDENTIFY_IP);
	memcpy(identify->ip, eap->adapter->ip, 4);
	identify->type_version = htons(IDENTIFY_VERSION);
	GetEncodedVersion(identify->version);
	identify->type_user = htons(IDENTIFY_USERNAME);
	memcpy(identify->user, eap->user, strlen(eap->user));
	
	int16_t len = sizeof(EAP_PACKET) + sizeof(IDENTIFY_FRM) + strlen(eap->user);
	packet->len1 = packet->len2 = htons(len-4);
	
	adapter_send_packet(eap->adapter, buf, len);
}

void eap_send_md5_response(EAP *eap)
{
	printf("[%ld]send: eap md5 challenge response\n", time(NULL));
	char buf[128] = {0};
	EAP_PACKET *packet = (EAP_PACKET *)buf;
	
	packet->version = 1;
	packet->pkt_type = EAP_EAP;
	packet->code = EAP_RESPONSE;
	packet->id = eap->id;
	packet->eap_type = EAP_MD5;

	MD5_FRM *md5_frm = (MD5_FRM *)packet->payload;
	
	md5_frm->len = 16;
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, (char *)&eap->id, sizeof(char));
	MD5Update(&md5, eap->passwd, strlen(eap->passwd));
	MD5Update(&md5, eap->md5_key, sizeof(eap->md5_key));
	MD5Final(&md5);
	memcpy(md5_frm->md5, md5.digest, sizeof(md5_frm->md5));
	memcpy(md5_frm->user, eap->user, strlen(eap->user));

	int16_t len = sizeof(EAP_PACKET) + sizeof(MD5_FRM) + strlen(eap->user);
	packet->len1 = packet->len2 = htons(len-4);

	adapter_send_packet(eap->adapter, buf, len);
}

void eap_send_allocated_response(EAP *eap)
{
	printf("[%ld]send: eap allocated response\n", time(NULL));
	char buf[128] = {0};
	EAP_PACKET *packet = (EAP_PACKET *)buf;
	
	packet->version = 1;
	packet->pkt_type = EAP_EAP;
	packet->code = EAP_RESPONSE;
	packet->id = eap->id;
	packet->eap_type = EAP_ALLOCATED;

	ALLOCATED_FRM *allocated = (ALLOCATED_FRM *)packet->payload;
	
	allocated->type = 0x0c; //I don't konw what is it actually mean
	memcpy(allocated->value, eap->user, strlen(eap->user));
	memcpy(allocated->value+strlen(eap->user), eap->passwd, strlen(eap->passwd));

	int16_t len = sizeof(EAP_PACKET) + sizeof(ALLOCATED_FRM) + strlen(eap->user) + strlen(eap->passwd);
	packet->len1 = packet->len2 = htons(len-4);

	adapter_send_packet(eap->adapter, buf, len);
}

void eap_event_loop(EAP *eap)
{
	char buf[1500];
	adapter_set_timeout(eap->adapter, 10);
	while(1) {
		memset(buf, 0, sizeof(buf));
		int n = adapter_get_packet(eap->adapter, buf, sizeof(buf));
		if (n < 0) {
			printf("[%ld]recv: timeout\n", time(NULL));
			goto failed;
		}
		EAP_PACKET *packet = (EAP_PACKET *)buf;
		if (packet->pkt_type == EAP_EAP) {
			switch(packet->code) {
				case EAP_REQUEST:
					eap->id = packet->id;
					switch(packet->eap_type) {
						case EAP_IDENTIFY:
							printf("[%ld]recv: eap identify request\n", time(NULL));
							eap_send_identify_response(eap);
							break;
						case EAP_MD5:
							printf("[%ld]recv: eap md5 challenge request\n", time(NULL));
							MD5_FRM *md5_frm = (MD5_FRM *)packet->payload;
							memcpy(eap->md5_key, md5_frm->md5, sizeof(md5_frm->md5));
							eap_send_md5_response(eap);
							break;
						case EAP_ALLOCATED:
							printf("[%ld]recv: eap allocated request\n", time(NULL));
							eap_send_allocated_response(eap);
							break;
						case EAP_LOGOUT:
						case EAP_ERROR:
						case EAP_NOTIFICATION:
							printf("[%ld]recv: unsupported eap request: 0x%x\n", time(NULL), (uint8_t)packet->eap_type);
							break;
					}
					break;
				case EAP_RESPONSE:
					break;
				case EAP_SUCCESS:
					printf("[%ld]recv: eap success\n", time(NULL));
					adapter_set_timeout(eap->adapter, 150);
					eap->retry_times = 0;
					break;
				case EAP_FAILURE:
					printf("[%ld]recv: eap failure\n", time(NULL));
					eap->retry_times++;
					goto failed;
					break;
				case EAP_OTHER:
				default:
					printf("[%ld]recv: unkonw eap packet\n", time(NULL));
					break;
			}
		}
	}
failed:
	return;
}
