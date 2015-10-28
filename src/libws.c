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

	h->url = 0;
	h->host = 0;
	h->origin = 0;
	h->key = 0;
	h->accept = 0;

	char* getStart = strstr(ss, "GET");
	char* httpStart = strstr(ss, "HTTP/1.1"); // Must be HTTP/1.1 (RFC6455)

	if(getStart == ss && httpStart != 0) {
		size_t urlLen = httpStart - getStart - 3 - 2;
		h->url = (char*)malloc(urlLen + 1);

		memcpy(h->url, (ss + 4), urlLen);
		h->url[urlLen] = '\0';

		char* connStart = strstr(ss, "Connection: ");
		if(connStart == 0 || strstr(connStart, "Upgrade") == 0) {
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
	int cursor = 0;
	u8 mask[4];

	bool fin = buf[cursor] & 0x80 >> 7;
	u8 opcode = buf[cursor] & 0x0f;
	cursor++;

	bool masked = buf[cursor] & 0x80 >> 7;
	u8 plen = buf[cursor] & 0x7f;
	cursor++;

	printf("Size: %lu // Fin: %d // Opcode: %d // Masked: %d // plen(1): %d\n", len, fin, opcode, masked, plen);

	// TODO: Handle plen > 125 

	if(masked && len > (size_t)cursor + 4) {
		memcpy(mask, buf + cursor, 4);
		cursor += 4;
	}
	else {
		// Invalid
	}

	data->base = (u8*)malloc(plen);
	data->len = plen;

	if(masked) {
		for(int i = 0; i < plen; ++i) {
			data->base[i] = (u8)(buf[cursor + i] ^ mask[i % 4]);
		}
	}
	else {
		memcpy(data->base, buf + cursor, plen);
	}

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
	if(h->url) {
		free(h->url);
	}
	if(h->host) {
		free(h->host);
	}
	if(h->origin) {
		free(h->origin);
	}
	if(h->key) {
		free(h->key);
	}
	if(h->accept) {
		free(h->accept);
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
