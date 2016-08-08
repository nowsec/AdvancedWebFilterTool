#define _CRT_SECURE_NO_WARNINGS
#include "header.h"
#include "windivert.h"

void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an empty blacklist.
*/
PBLACKLIST BlackListInit(void)
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));
	UINT size;
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;
	blacklist->urls = (PURL *)malloc(size*sizeof(PURL));
	if (blacklist->urls == NULL)
	{
		goto memory_error;
	}
	blacklist->size = size;
	blacklist->length = 0;

	return blacklist;

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* URL comparison.
*/
int __cdecl UrlCompare(const void *a, const void *b)
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);
}

/*
* Sort the blacklist (for searching).
*/
void BlackListSort(PBLACKLIST blacklist)
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* URL matching
*/
static int UrlMatch(PURL urla, PURL urlb)
{
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}

/*
* Match a URL against the blacklist.
*/
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)
{
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;
		}
	}
	return FALSE;
}


/*
* Insert a URL into a blacklist.
*/
void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size*sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;
}


/*
* Read URLs from a file.
*/
void BlackListRead(PBLACKLIST blacklist, const char *filename)
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");

	if (file == NULL)
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	// Read URLs from the file and add them to the blacklist: 
	while (TRUE)
	{
		while (isspace(c = getc(file)))
			;
		if (c == EOF)
		{
			break;
		}
		if (c != '-' && !isalnum(c))
		{
			while (!isspace(c = getc(file)) && c != EOF)		//isspace 공백이 아니면 0이 아닌 값을 반환한다.
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)		//isalnum 숫자나 문자가 아니면 0이 아닌 값이 들어간다.
		{
			domain[i++] = (char)c;
		}
		domain[i] = '\0';
		j = 0;
		if (c == '/')
		{
			while (!isspace(c = getc(file)) && c != EOF && j < MAXURL)
			{
				uri[j++] = (char)c;
			}
			uri[j] = '\0';
		}
		else if (isspace(c))
		{
			uri[j] = '\0';
		}
		else
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			continue;
		}

		printf("ADD %s/%s\n", domain, uri);

		url = (PURL)malloc(sizeof(URL));
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1)*sizeof(char));
		url->uri = (char *)malloc((j + 1)*sizeof(char));
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];
		}
		url->domain[j] = '\0';

		BlackListInsert(blacklist, url);
	}

	fclose(file);
	return;

memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}

/*
* Attempt to parse a URL and match it with the blacklist.
*
* BUG:
* - This function makes several assumptions about HTTP requests, such as:
*      1) The URL will be contained within one packet;
*      2) The HTTP request begins at a packet boundary;
*      3) The Host header immediately follows the GET/POST line.
*   Some browsers, such as Internet Explorer, violate these assumptions
*   and therefore matching will not work.
*/
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site)
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str)+sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str)-1) == 0)
	{
		i += sizeof(get_str)-1;
	}
	else if (strncmp(data, post_str, sizeof(post_str)-1) == 0)
	{
		i += sizeof(post_str)-1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str)-1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str)-1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str)-1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		// Nice try...
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';

	printf("URL %s/%s: ", domain, uri);
	memcpy(blockedDomain_site, domain, sizeof(domain));
	// Reverse the domain:
	for (i = 0; i < j / 2; i++)
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// Search the blacklist:
	result = BlackListMatch(blacklist, &url);

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		printf("BLOCKED! ");
	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;
}

