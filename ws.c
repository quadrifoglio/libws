#include "ws.h"

#include <string.h>
#include <stdio.h>

#ifdef __BIG_ENDIAN__
# define SHA_BIG_ENDIAN
#elif defined __LITTLE_ENDIAN__
/* override */
#elif defined __BYTE_ORDER
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define SHA_BIG_ENDIAN
# endif
#else // ! defined __LITTLE_ENDIAN__
# include <endian.h> // machine/endian.h
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
#  define SHA_BIG_ENDIAN
# endif
#endif

/*
 * Base64 Encoding
 * https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64
 */

int b64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize) {
	const char b64chrs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *data = (const uint8_t *)data_buf;
	size_t resultIndex = 0;
	size_t x;
	uint32_t n = 0;
	int padCount = dataLength % 3;
	uint8_t n0, n1, n2, n3;

	for (x = 0; x < dataLength; x += 3) {
		n = ((uint32_t)data[x]) << 16;

		if((x+1) < dataLength)
		n += ((uint32_t)data[x+1]) << 8;

		if((x+2) < dataLength)
		n += data[x+2];

		n0 = (uint8_t)(n >> 18) & 63;
		n1 = (uint8_t)(n >> 12) & 63;
		n2 = (uint8_t)(n >> 6) & 63;
		n3 = (uint8_t)n & 63;

		if(resultIndex >= resultSize)
			return 1;

		result[resultIndex++] = b64chrs[n0];

		if(resultIndex >= resultSize)
			return 1;

		result[resultIndex++] = b64chrs[n1];

		if((x+1) < dataLength) {
			if(resultIndex >= resultSize)
				return 1;

			result[resultIndex++] = b64chrs[n2];
		}

		if((x+2) < dataLength) {
			if(resultIndex >= resultSize)
				return 1;

			result[resultIndex++] = b64chrs[n3];
		}
	}

	if(padCount > 0) {
		for (; padCount < 3; padCount++) {
			if(resultIndex >= resultSize)
				return 1;

			result[resultIndex++] = '=';
		}
	}

	if(resultIndex >= resultSize)
		return 1;

	result[resultIndex] = 0;
	return 0;
}

/*
 * End base64
 */

/*
 * SHA1 encoding
 * https://oauth.googlecode.com/svn/code/c/liboauth/src/sha1.c
 */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {
	uint32_t buffer[BLOCK_LENGTH/4];
	uint32_t state[HASH_LENGTH/4];
	uint32_t byteCount;
	uint8_t bufferOffset;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

#define SHA1_K0  0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

void sha1_init(sha1nfo *s) {
	s->state[0] = 0x67452301;
	s->state[1] = 0xefcdab89;
	s->state[2] = 0x98badcfe;
	s->state[3] = 0x10325476;
	s->state[4] = 0xc3d2e1f0;
	s->byteCount = 0;
	s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
	return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
	uint8_t i;
	uint32_t a,b,c,d,e,t;

	a=s->state[0];
	b=s->state[1];
	c=s->state[2];
	d=s->state[3];
	e=s->state[4];
	for (i=0; i<80; i++) {
		if (i>=16) {
			t = s->buffer[(i+13)&15] ^ s->buffer[(i+8)&15] ^ s->buffer[(i+2)&15] ^ s->buffer[i&15];
			s->buffer[i&15] = sha1_rol32(t,1);
		}
		if (i<20) {
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		} else if (i<40) {
			t = (b ^ c ^ d) + SHA1_K20;
		} else if (i<60) {
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		} else {
			t = (b ^ c ^ d) + SHA1_K60;
		}
		t+=sha1_rol32(a,5) + e + s->buffer[i&15];
		e=d;
		d=c;
		c=sha1_rol32(b,30);
		b=a;
		a=t;
	}
	s->state[0] += a;
	s->state[1] += b;
	s->state[2] += c;
	s->state[3] += d;
	s->state[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
	uint8_t * const b = (uint8_t*) s->buffer;
#ifdef SHA_BIG_ENDIAN
	b[s->bufferOffset] = data;
#else
	b[s->bufferOffset ^ 3] = data;
#endif
	s->bufferOffset++;
	if (s->bufferOffset == BLOCK_LENGTH) {
		sha1_hashBlock(s);
		s->bufferOffset = 0;
	}
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
	++s->byteCount;
	sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
	// Implement SHA-1 padding (fips180-2 §5.1.1)

	// Pad with 0x80 followed by 0x00 until the end of the block
	sha1_addUncounted(s, 0x80);
	while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

	// Append length in the last 8 bytes
	sha1_addUncounted(s, 0); // We're only using 32 bit lengths
	sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
	sha1_addUncounted(s, 0); // So zero pad the top bits
	sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
	sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
	sha1_addUncounted(s, s->byteCount >> 13); // byte.
	sha1_addUncounted(s, s->byteCount >> 5);
	sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
	// Pad to complete the last block
	sha1_pad(s);

#ifndef SHA_BIG_ENDIAN
	// Swap byte order back
	int i;
	for (i=0; i<5; i++) {
		s->state[i]=
			(((s->state[i])<<24)   & 0xff000000)
			| (((s->state[i])<<8)  & 0x00ff0000)
			| (((s->state[i])>>8)  & 0x0000ff00)
			| (((s->state[i])>>24) & 0x000000ff);
	}
#endif

	// Return pointer to hash (20 characters)
	return (uint8_t*) s->state;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength) {
	uint8_t i;
	memset(s->keyBuffer, 0, BLOCK_LENGTH);
	if (keyLength > BLOCK_LENGTH) {
		// Hash long keys
		sha1_init(s);
		for (;keyLength--;) sha1_writebyte(s, *key++);
		memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
	} else {
		// Block length keys are used as is
		memcpy(s->keyBuffer, key, keyLength);
	}
	// Start inner hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) {
		sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
	}
}

uint8_t* sha1_resultHmac(sha1nfo *s) {
	uint8_t i;
	// Complete inner hash
	memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
	// Calculate outer hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
	for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
	return sha1_result(s);
}

/*
 * End SHA1
 */

int ws_handshake_process(ws_handshake_t* h, int sock) {
	// TODO: Remove when finished debuging
	/*if(len < 150) {
		return WS_ERR_INVALID_REQUEST;
	}*/

	/*char* ss = (char*)malloc(len + 1);
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

		h->accept = (char*)malloc(64 + 1);
		b64encode((const void*)hash, 20, h->accept, 64 + 1);

		free(sc);
	}
	else {
		free(ss);
		return WS_ERR_INVALID_REQUEST;
	}

	free(ss);*/
	return WS_NO_ERR;
}

int ws_frame_process(ws_frame_t* f, int sock) {
	/*int cursor = 0;
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
		length =
			(u64)buf[cursor + 0] << 56 | (u64)buf[cursor + 1] << 48 |
			(u64)buf[cursor + 2] << 40 | (u64)buf[cursor + 3] << 32 |
			(u64)buf[cursor + 4] << 24 | (u64)buf[cursor + 5] << 16 |
			(u64)buf[cursor + 6] << 8  | (u64)buf[cursor + 7] << 0;

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
		f->data.base = (u8*)malloc(length);
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
	}*/

	return WS_ERR_INVALID_FRAME;
}

ws_data_t ws_frame_create(u8 type, char* buf, size_t len) {
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
		lenBytes[6] = (len >> 8)  & 0xff;
		lenBytes[7] = (len >> 0)  & 0xff;
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
	d.len = strlen((char*)d.base);

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

ws_data_t ws_data_nit(u8* base, size_t len) {
	ws_data_t res = { base, len };
	return res;
}

void ws_data_done(ws_data_t* d) {
	free(d->base);
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
	if(start == 0) {
		return 0;
	}

	char* endlStart = strstr(start, "\r\n");
	if(endlStart == 0) {
		return 0;
	}

	size_t len = endlStart - (start + strlen(hd));
	char* res = (char*)malloc(len + 1);
	memcpy(res, start + strlen(hd), len);
	res[len] = '\0';

	return res;
}

void wsu_dump_frame(ws_frame_t* f) {
	char* s = (char*)malloc(f->data.len + 2);
	memcpy(s, f->data.base, f->data.len);
	s[f->data.len] = '\0';

	printf("-- Frame --\n");
	printf("Type           : |%d|\n", f->type);
	printf("Fin            : |%d|\n", f->fin);
	printf("Payload length : |%zu|\n", f->data.len);
	printf("Payload        : |%s|\n", s);
	printf("-- End --\n");

	free(s);
}
