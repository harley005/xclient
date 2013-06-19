#ifndef	__EAP_H__
#define __EAP_H__

#include "adapter.h"

//POCKET TYPE CODE
#define EAP_EAP				0x00
#define	EAP_START			0x01
#define	EAP_LOGOFF			0x02

//EAP HEAD CODE
#define	EAP_REQUEST			0x01
#define	EAP_RESPONSE		0x02
#define	EAP_SUCCESS			0x03
#define	EAP_FAILURE			0x04
#define	EAP_OTHER			0x0a

//EAP DATA TYPE
#define	EAP_IDENTIFY		0x01
#define	EAP_NOTIFICATION	0x02
#define	EAP_MD5				0X04
#define	EAP_ALLOCATED		0X07
#define	EAP_LOGOUT			0X08
#define	EAP_ERROR			0X09
#define	EAP_KEEPONLINE		0X14

//IDENTIFY DATA TYPE
#define	IDENTIFY_IP			0x1504
#define IDENTIFY_VERSION	0x0607
#define IDENTIFY_USERNAME	0x2020

typedef struct _EAP
{
	ADAPTER	*adapter;
	int 	id;
	int 	retry_times;
	int 	multicast;
	char	md5_key[16];
	char 	user[20];
	char	passwd[20];
} EAP;

#pragma pack(1)
typedef struct _EAP_PACKET
{
	char	version;
	char	pkt_type;
	int16_t	len1;

	char	code;
	char	id;
	int16_t	len2;

	char	eap_type;
	char	payload[];
} EAP_PACKET;

typedef struct _IDENTIFY_FRM
{
	int16_t type_ip;
	char	ip[4];
	int16_t type_version;
	char	version[28];
	int16_t type_user;
	char	user[];
} IDENTIFY_FRM;

typedef struct _MD5_FRM
{
	char	len;
	char	md5[16];
	char	user[];
} MD5_FRM;

typedef struct _ALLOCATED_FRM
{
	char	type;
	char	value[];
} ALLOCATED_FRM;

#pragma pack()


EAP *eap_open(char *adapter_name, char *user, char *passwd);
void eap_release(EAP *eap);
void eap_send_start(EAP *eap);
void eap_send_logoff(EAP *eap);
void eap_send_identify_response(EAP *eap);
void eap_send_md5_response(EAP *eap);
void eap_send_allocated_response(EAP *eap);
void eap_event_loop(EAP *eap);


#endif
