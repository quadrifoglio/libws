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

int ws_process_frame(ws_frame_t* f, char* buf, size_t len) {
	int cursor = 0;
	u64 length = 0;
	u8 mask[4];

	bool fin = (buf[cursor] & 0x80) != 0;
	u8 opcode = buf[cursor] & 0x0f;
	cursor++;

	bool masked = (buf[cursor] & 0x80) != 0;
	u8 plen = buf[cursor] & 0x7f;
	cursor++;

	if(plen <= 125) {
		length = plen;
	}
	else if(plen == 126 && len > (size_t)cursor + 2) {
		length = (u8)buf[cursor] << 8 | (u8)buf[cursor+1] << 0;
		cursor += 2;
	}
	else if(plen == 127 && len > (size_t)cursor + 8) {
		length = (u64)buf[cursor] << 56 | (u64)buf[cursor + 1] << 48 |
			(u64)buf[cursor + 2] << 40 | (u64)buf[cursor + 3] << 32 |
			(u64)buf[cursor + 4]  << 24 | (u64)buf[cursor + 5] << 16 |
			(u64)buf[cursor + 6] << 8 | (u64)buf[cursor + 7] << 0;

		cursor += 8;
	}
	else {
		return WS_ERR_INVALID_FRAME;
	}

	if(masked && len > (size_t)cursor + 4) {
		memcpy(mask, buf + cursor, 4);
		cursor += 4;
	}
	else {
		return WS_ERR_INVALID_FRAME;
	}

	if(len - cursor == length) {
		f->data.base = (u8*)malloc(plen);
		f->data.len = length;

		if(masked) {
			for(int i = 0; (u64)i < length; ++i) {
				f->data.base[i] = (u8)(buf[cursor + i] ^ mask[i % 4]);
			}
		}
		else {
			memcpy(f->data.base, buf + cursor, length);
		}

		f->fin = fin;
		f->type = opcode;

		return WS_NO_ERR;
	}

	return WS_ERR_INVALID_FRAME;
}

ws_data_t ws_create_frame(u8 type, char* buf, size_t len) {
	ws_data_t res;

	u8 b0 = (0x8 << 4) | type;
	u8 lenField = 0;

	if(len <= 125) {
		lenField = len;

		res.len = 2 + len;
		res.base = malloc(res.len);

		res.base[0] = b0;
		res.base[1] = lenField;
		memcpy(res.base + 2, buf, len);
	}
	else if(len < 65536) {
		u8 lenBytes[2];

		lenBytes[0] = (len >> 8) & 0xff;
		lenBytes[1] = (len >> 0) & 0xff;
		lenField = 126;

		res.len = 2 + 2 + len;
		res.base = malloc(res.len);

		res.base[0] = b0;
		res.base[1] = lenField;
		memcpy(res.base + 2, lenBytes, 2);
		memcpy(res.base + 4, buf, len);
	}
	else {
		u8 lenBytes[8];

		lenBytes[0] = (len >> 56) & 0xff;
		lenBytes[1] = (len >> 48) & 0xff;
		lenBytes[2] = (len >> 40) & 0xff;
		lenBytes[3] = (len >> 32) & 0xff;
		lenBytes[4] = (len >> 24) & 0xff;
		lenBytes[5] = (len >> 16) & 0xff;
		lenBytes[6] = (len >> 8) & 0xff;
		lenBytes[7] = (len >> 0) & 0xff;
		lenField = 127;

		res.len = 2 + 8 + len;
		res.base = malloc(res.len);

		res.base[0] = b0;
		res.base[1] = lenField;
		memcpy(res.base + 2, lenBytes, 8);
		memcpy(res.base + 10, buf, len);
	}

	return res;
}

ws_data_t ws_handshake_response(ws_handshake_t* h) {
	ws_data_t d;

	d.len = strlen(WS_HANDSHAKE_RESP) + strlen(h->accept);
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
		case WS_ERR_INVALID_FRAME:
			return "invalid websocket frame";
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

void wsu_dump_frame(ws_frame_t* f) {
	char* s = (char*)malloc(f->data.len + 1);
	memcpy(s, f->data.base, f->data.len);
	s[f->data.len] = '\0';

	printf("-- Frame --\n");
	printf("Type           : |%d|\n", f->type);
	printf("Fin            : |%d|\n", f->fin);
	printf("Payload length : |%d|\n", f->data.len);
	printf("Payload        : |%s|\n", s);
	printf("-- End --\n");

	free(s);
}
