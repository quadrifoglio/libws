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

		h->host = wsu_get_header_value("Host: ", ss);
		if(h->host == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		h->origin = wsu_get_header_value("Origin: ", ss);
		if(h->origin == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		h->key = wsu_get_header_value("Sec-WebSocket-Key: ", ss);
		if(h->key == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}
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

char* wsu_get_header_value(const char* hd, char* str) {
	char* start = strstr(str, hd);
	char* endlStart = strstr(start, "\r\n");
	if(start == 0 || endlStart == 0) {
		return 0;
	}

	size_t len = endlStart - (start + strlen(hd));
	char* res = (char*)malloc(len + 1);
	memcpy(res, start + strlen(hd), len);
	res[len] = '\0';

	return res;
}
