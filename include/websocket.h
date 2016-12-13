#pragma once

#include <stddef.h>
#include <sys/types.h>

/*
 * Public API functionality
 */

struct wsStatus {
	int version; // WebSocket protocol version
	char* url;   // WebSocket requested URL
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
 * Internal utility functionality
 */

ssize_t wsReadLine(int sockfd, void* buf, size_t len);
int wsRegexMatches(const char* regex, const char* str, char** matches);
