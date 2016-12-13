#include "websocket.h"
#include "sha1.h"

#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

/*
 * Public API functionality
 */

int wsHandshake(int sockfd, struct wsStatus* status) {
	char* wsKey = 0;

	char buf[256] = {0};
	if(wsReadLine(sockfd, buf, 256) < 0) {
		return 0;
	}

	char* matches[2] = {0};

	int n = wsRegexMatches("GET (\\/.*) HTTP\\/1\\.1", buf, matches);
	if(n != 2) {
		for(int i = 0; i < n; i++) {
			free(matches[i]);
		}

		return 0;
	}

	free(matches[0]);
	status->url = matches[1];

	while(1) {
		if(wsReadLine(sockfd, buf, 256) < 0) {
			return 0;
		}

		if(strlen(buf) == 2) {
			break; // End of headers
		}

		char* matches[2] = {0};

		int n = wsRegexMatches("Sec-WebSocket-Version: ([0-9]*)", buf, matches);
		if(n == 2) {
			status->version = atoi(matches[1]);
			if(status->version <= 0) {
				goto endloop;
			}
		}

		for(int i = 0; i < n; i++) {
			free(matches[i]);
		}

		n = wsRegexMatches("Sec-WebSocket-Key: (.*)", buf, matches);
		if(n == 2) {
			wsKey = strdup(matches[1]);
			wsKey[strlen(wsKey) - 2] = 0; // Delete the new-line character
		}

endloop:
		for(int i = 0; i < n; i++) {
			free(matches[i]);
		}
	}

	if(!status->version || !status->url || !wsKey) {
		return 0;
	}

	static const char* resp =
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Connection: Upgrade\r\n"
		"Upgrade: websocket\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"\r\n";

	static const char* wtf = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	char* c = calloc(1, strlen(wsKey) + strlen(wtf) + 1);
	memcpy(c, wsKey, strlen(wsKey));
	memcpy(c + strlen(wsKey), wtf, strlen(wtf));

	free(wsKey);

	SHA1_CTX sha;
	unsigned char hash[20];

	SHA1Init(&sha);
	SHA1Update(&sha, (unsigned char*)c, strlen(c));
	SHA1Final(hash, &sha);

	size_t s;
	char* enc = wsB64((char*)hash, 20, &s);
	enc = realloc(enc, s + 1);
	enc[s] = 0;

	free(c);

	s = strlen(resp) - 2 + strlen(enc);
	char* r = malloc(s + 1);

	sprintf(r, resp, enc);
	free(enc);

	send(sockfd, r, s, 0);
	free(r);

	return 1;
}

void wsStatusFree(const struct wsStatus* s) {
	free(s->url);
}

/*
 * Inernal utility functionality
 */

int wsRegexMatches(const char* regex, const char* str, char** matches) {
	regex_t r = {0};
	if(regcomp(&r, regex, REG_EXTENDED) != 0) {
		return 0;
	}

	int nmatch = r.re_nsub + 1;
	regmatch_t* rmatches = malloc(nmatch * sizeof(regmatch_t));

	if(regexec(&r, str, nmatch, rmatches, 0) != 0) {
		free(rmatches);
		return 0;
	}

	for(int i = 0; i < nmatch; i++) {
		regmatch_t m = rmatches[i];

		if(m.rm_so < 0) {
			break; // End of matches
		}

		char* r = calloc(1, m.rm_eo - m.rm_so + 1);
		memcpy(r, str + m.rm_so, m.rm_eo - m.rm_so);
		matches[i] = r;
	}

	free(rmatches);
	return nmatch;
}

ssize_t wsReadLine(int sockfd, void* buf, size_t len) {
	char* sbuf = (char*)buf;
	int i = 0;

	while(i <= (int)len) {
		char byte;
		if(recv(sockfd, &byte, 1, 0) != 1) {
			return -1;
		}

		sbuf[i++] = byte;

		if(byte == '\n') {
			sbuf[i++] = 0; // End of string
			break;
		}
	}

	return i - 2;
}

// http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
char* wsB64(const char* data, size_t len, size_t* outLen) {
	static const char encoding_table[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/'
	};

	static const int mod_table[] = {0, 2, 1};

	*outLen = 4 * ((len + 2) / 3);
	char *enc = calloc(1, *outLen);

	for (size_t i = 0, j = 0; i < len;) {
		uint32_t octet_a = i < len ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < len ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < len ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		enc[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		enc[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		enc[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		enc[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[len % 3]; i++)
	enc[*outLen - 1 - i] = '=';

	return enc;
}
