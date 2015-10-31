#pragma once

#include <stdlib.h>
#include <stdint.h>

#define false 0
#define true 1

#define WS_CR 0x0d
#define Ws_LF 0x0a

#define WS_FRAME_CONTINUATION 0x0
#define WS_FRAME_TEXT 0x1
#define WS_FRAME_BINARY 0x2
#define WS_FRAME_CLOSE 0x8
#define WS_FRAME_PING 0x9
#define WS_FRAME_PONG 0x

#define WS_NO_ERR 0
#define WS_ERR_INVALID_REQUEST 1
#define WS_ERR_INVALID_FRAME 2

#define WS_HANDSHAKE_RESP \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n" \
	"Connection: Upgrade\r\n" \
	"Sec-WebSocket-Accept: %s\r\n\r\n" \

typedef uint8_t bool;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef struct {
	char* url;
	char* host;
	char* origin;
	char* key;
	char* accept;
} ws_handshake_t;

typedef struct {
	u8* base;
	size_t len;
} ws_data_t;

typedef struct {
	u8 type;
	bool fin;
	ws_data_t data;
} ws_frame_t;

int ws_process_handshake(ws_handshake_t* h, char* buf, size_t len);
ws_data_t ws_handshake_response(ws_handshake_t* h);
void ws_handshake_done(ws_handshake_t* h);

int ws_process_frame(ws_frame_t* f, char* buf, size_t len);
ws_data_t ws_create_frame(u8 type, char* buf, size_t len);

ws_data_t ws_data_nit(u8* base, size_t len);
void ws_data_done(ws_data_t* d);

const char* ws_err_name(int r);

char* wsu_get_header_value(const char* hd, char* start);
void wsu_dump_frame(ws_frame_t* f);
