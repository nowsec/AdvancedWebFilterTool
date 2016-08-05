#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096


/*
* URL and blacklist representation.
*/
typedef struct url
{
	char *domain;
	char *uri;
} URL, *PURL;
typedef struct blacklist
{
	UINT size;
	UINT length;
	PURL *urls;
} BLACKLIST, *PBLACKLIST;

/*
* Pre-fabricated packets.
*/
typedef struct ipandtcp
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct datapacket
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;