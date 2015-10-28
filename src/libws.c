#include "libws.h"

#include <string.h>
#include <stdio.h>
#include "lib/sha1.h"
#include "lib/base64.h"

int ws_process_handshake(ws_handshake_t* h, char* buf, size_t len) {
	// TODO: Remove when finished debuging
	/*if(len < 150) {
		return WS_ERR_INVALID_REQUEST;
	}*/

	char* ss = (char*)malloc(len + 1);
	memcpy(ss, buf, len);
	ss[len - 1] = '\0';

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

		h->key = wsu_get_header_value("Sec-WebSocket-Key: ", ss);
		if(h->key == 0) {
			free(ss);
			return WS_ERR_INVALID_REQUEST;
		}

		h->origin = wsu_get_header_value("Origin: ", ss);

		char* sc = (char*)malloc(strlen(h->key) + 36 + 1);
		strcpy(sc, h->key);
		strcat(sc, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

		sha1nfo s;
		sha1_init(&s);
		sha1_write(&s, sc, strlen(sc));
		u8* hash = sha1_result(&s);

		h->accept = (char*)malloc(64);
		encode64((char*)hash, h->accept, 20);

		free(sc);
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

ws_data_t ws_handshake_response(ws_handshake_t* h) {
	ws_data_t d;

	d.len = strlen(WS_HANDSHAKE_RESP) + 64;
	d.base = (u8*)malloc(d.len);

	sprintf((char*)d.base, WS_HANDSHAKE_RESP, h->accept);
	return d;
}

void ws_handshake_done(ws_handshake_t* h) {
	free(h->url);
	free(h->host);
	free(h->key);
	free(h->accept);

	if(h->origin) {
		free(h->origin);
	}
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
