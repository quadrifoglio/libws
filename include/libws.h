#pragma once

#include <stdlib.h>
#include <stdint.h>

#define false 0
#define true 1

#define WS_CR 0x0d
#define Ws_LF 0x0a

#define WS_NO_ERR 0
#define WS_ERR_INVALID_REQUEST 1

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
} ws_handshake_t;

typedef enum {
	WS_TEXT_FRAME,
	WS_DATA_FRAME
} ws_type_t;

typedef struct {
	u8* base;
	size_t len;
} ws_data_t;

typedef struct {
	ws_type_t type;
	ws_data_t data;
} ws_frame_t;

int ws_process_handshake(ws_handshake_t* h, char* buf, size_t len);
void ws_handshake_done(ws_handshake_t* h);

int ws_process_frame(ws_data_t* data, char* buf, size_t len);
ws_frame_t ws_create_frame(ws_type_t type, char* buf, size_t len);

const char* ws_err_name(int r);

char* wsu_get_header_value(const char* hd, char* start);
