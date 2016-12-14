#pragma once

#include <stddef.h>
#include <sys/types.h>

/*
 * -- Public API functionality
 */

/*
 * Frame opcodes
 */
#define WS_OPCODE_CONTINUE     0x0
#define WS_OPCODE_FRAME_TEXT   0x1
#define WS_OPCODE_FRAME_BINARY 0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xa

/*
 * Library settings
 */
#define WS_MAX_PAYLOAD_ALLOC   16384

struct wsStatus {
	int version; // WebSocket protocol version
	char* url;   // WebSocket requested URL
};

struct wsMessage {
	int type; // Type of the payload data

	size_t len;    // Payload length
	void* payload; // Pointer to the payload data
};

/*
 * Process a WebSocket handshake and populate
 * the wsStatus struct accordingly
 */
int wsHandshake(int sockfd, struct wsStatus* status);

/*
 * Free the resources associated to
 * the wsStatus struct
 */
void wsStatusFree(const struct wsStatus* s);

/*
 * Receive a WebSocket message
 */
int wsRecv(int sockfd, struct wsMessage* msg);

/*
 * Send a WebSocket message
 */
int wsSend(int sockfd, int type, void* buf, size_t len);

/*
 * Free the resources associated
 * with a wsMessage struct
 */
void wsMessageFree(const struct wsMessage* msg);
