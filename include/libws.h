#pragma once

#include <stdlib.h>
#include <stdint.h>

#define false 0
#define true 1

typedef uint8_t bool;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef enum {
	WS_TEXT_FRAME,
	WS_DATA_FRAME
} ws_type_t;

typedef struct {
	ws_type_t type;
} ws_frame_t;

typedef struct {
	u8* data;
	size_t len;
} ws_data_t;

char* ws_process_handshake(char* data, size_t len);
ws_data_t ws_process_frame(char* data, size_t len);
ws_frame_t ws_create_frame(ws_type_t type, char* data, size_t len);
