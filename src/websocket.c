#include "websocket.h"

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

		int n = wsRegexMatches("Sec-Websocket-Version: ([0-9]*)", buf, matches);
		if(n == 2) {
			status->version = atoi(matches[1]);
			if(status->version <= 0) {
				goto endloop;
			}
		}

		for(int i = 0; i < n; i++) {
			free(matches[i]);
		}

		n = wsRegexMatches("Sec-Websocket-Key: (.*)", buf, matches);
		if(n == 2) {
			wsKey = strdup(matches[1]);
			wsKey[strlen(wsKey) - 1] = 0; // Delete the new-line character
		}

endloop:
		for(int i = 0; i < n; i++) {
			free(matches[i]);
		}
	}

	if(!status->version || !status->url || !wsKey) {
		return 0;
	}

end:
	return 1;
}

void wsStatusFree(const struct wsStatus* s) {
	free(s->url);
}

/*
 * Inernal utility functionality/
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
