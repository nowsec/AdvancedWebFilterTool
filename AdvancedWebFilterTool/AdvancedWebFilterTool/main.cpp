#define _CRT_SECURE_NO_WARNINGS
#include "header.h"

typedef struct url URL, *PURL;
typedef struct blacklist BLACKLIST, *PBLACKLIST;
typedef struct ipandtcp PACKET, *PPACKET;
typedef struct datapacket DATAPACKET, *PDATAPACKET;

const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>This URL has been blocked!</p>\n"
"\t</body>\n"
"</html>\n";

/*
* Prototypes
*/

char blockedDomain[MAXURL];

void PacketInit(PPACKET packet);
int __cdecl UrlCompare(const void *a, const void *b);
int UrlMatch(PURL urla, PURL urlb);
PBLACKLIST BlackListInit(void);
void BlackListInsert(PBLACKLIST blacklist, PURL url);
void BlackListSort(PBLACKLIST blacklist);
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);
void BlackListRead(PBLACKLIST blacklist, const char *filename);
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site);
static bool mal_site_state;
/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	FILE *f_log_txt;
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;
	PBLACKLIST blacklist;
	unsigned i;
	INT16 priority = 404;       // Arbitrary.
	FILE *f_malsite_txt;
	mal_site_state = false;
	char buf[1024] = { 0, };
	// Read the blacklists.

	blacklist = BlackListInit();
	
	//f_malsite_txt = fopen("mal_site.txt", "r");
	BlackListRead(blacklist, "mal_site.txt");

	BlackListSort(blacklist);

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET)+sizeof(block_data)-1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;
	blockpage->header.tcp.Ack = 1;
	memcpy(blockpage->data, block_data, sizeof(block_data)-1);
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketInit(finish);
	finish->tcp.Fin = 1;
	finish->tcp.Ack = 1;

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
		);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// Main loop:
	while (TRUE)
	{
		f_log_txt = fopen("log.txt", "a");

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len, blockedDomain))
		{
			// Packet does not match the blacklist; simply reinject it.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data)-1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}

		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", blockedDomain,
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fclose(f_log_txt);
		}

	}
}




