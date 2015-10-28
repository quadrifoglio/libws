#include "libws.h"

#include <string.h>
#include <stdio.h>

int ws_process_handshake(ws_handshake_t* h, char* buf, size_t len) {
	// TODO: Remove when finished debuging
	/*if(len < 150) {
		return WS_ERR_INVALID_REQUEST;
	}*/

	char* ss = (char*)malloc(len + 1);
	memcpy(ss, buf, len);
	ss[len - 1] = '\0';

	printf("%s\n", ss);

	char* getStart = strstr(ss, "GET");
	char* httpStart = strstr(ss, "HTTP/1.1"); // Must be HTTP/1.1 (RFC6455)

	if(getStart == ss && httpStart != 0) {
		size_t urlLen = httpStart - getStart - 3 - 2;
		h->url = (char*)malloc(urlLen + 1);

		memcpy(h->url, (ss + 4), urlLen);
		h->url[urlLen] = '\0';

		char* connStart = strstr(ss, "Connection: Upgrade");
		if(connStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		char* upgStart = strstr(ss, "Upgrade: websocket");
		if(upgStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		char* verStart = strstr(ss, "Sec-WebSocket-Version: 13");
		if(verStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		char* hostStart = strstr(ss, "Host: ");
		char* endlStart = strstr(hostStart, "\r\n");
		if(hostStart == 0 || endlStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		size_t hostLen = endlStart - (hostStart + 5);
		h->host = (char*)malloc(hostLen + 1);
		memcpy(h->host, hostStart + 6, hostLen);
		h->host[hostLen] = '\0';

		char* originStart = strstr(ss, "Origin: ");
		endlStart = strstr(originStart, "\r\n");
		if(originStart == 0 || endlStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		size_t originLen = endlStart - (originStart + 7);
		h->origin = (char*)malloc(originLen + 1);
		memcpy(h->origin, originStart + 8, originLen);
		h->origin[originLen] = '\0';

		char* keyStart = strstr(ss, "Sec-WebSocket-Key: ");
		endlStart = strstr(keyStart, "\r\n");
		if(keyStart == 0 || endlStart == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		size_t keyLen = endlStart - (keyStart + 18);
		h->key = (char*)malloc(keyLen + 1);
		memcpy(h->key, keyStart + 19, keyLen);
		h->key[keyLen] = '\0';
	}
	else {
		free(ss);
		return WS_ERR_INVALID_REQUEST;
	}

	free(ss);
	return WS_NO_ERR;
}

int ws_process_frame(ws_data_t* data, char* buf, size_t len) {
	return WS_NO_ERR;
}

ws_frame_t ws_create_frame(ws_type_t type, char* buf, size_t len) {
	ws_frame_t res;
	return res;
}

void ws_handshake_done(ws_handshake_t* h) {
	free(h->url);
	free(h->host);
	free(h->origin);
	free(h->key);
}

const char* ws_err_name(int r) {
	switch(r) {
		case WS_NO_ERR:
			return "no error";
		case WS_ERR_INVALID_REQUEST:
			return "invalid opening handshake";
		default:
			return "unknown error";
	}
}
