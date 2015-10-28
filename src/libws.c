#include "libws.h"

#include <string.h>

int ws_process_handshake(ws_handshake_t* h, char* buf, size_t len) {
	// TODO: Remove when finished debuging
	/*if(len < 150) {
		return WS_ERR_INVALID_REQUEST;
	}*/

	char* ss = (char*)malloc(len + 1);
	memcpy(ss, buf, len);
	ss[len - 1] = '\0';

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
