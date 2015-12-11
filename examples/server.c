#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <libmill.h>

#include "libws.h"

ws_data_t get_handshake_request(tcpsock sock) {
	ws_data_t data;
	data.base = malloc(1);
	data.len = 1;
	size_t cur = 0;

	i64 dl = now() + 2000;
	do {
		u8 buf[256];
		size_t received = tcprecvuntil(sock, buf, 256, "\r", 1, dl);
		if(received == 0) {
			break;
		}

		data.base = realloc(data.base, data.len + received);
		memcpy(data.base + cur, buf, received);

		cur += received;
		data.len += received;
		dl = now() + 5;
	} while(1);

	return data;
}

coroutine void client(tcpsock sock) {
	ws_data_t d = get_handshake_request(sock);
	if(d.len < 30) {
		fputs("Invalid handshake request", stderr);
		goto cleanup;
	}

	ws_handshake_t hs;
	int r = ws_process_handshake(&hs, (char*)d.base, d.len);
	if(r) {
		fputs("Invalid handshake request", stderr);
		goto cleanup;
	}
	else {
		//printf("Client connected to URL \"%s\" from origin \"%s\"\n", hs.url, hs.origin);

		ws_data_t response = ws_handshake_response(&hs);
		tcpsend(sock, response.base, response.len, -1);
		tcpflush(sock, -1);

		ws_handshake_done(&hs);

		while(1) {
			u8 buf[256];
			size_t received = tcprecv(sock, buf, 256, -1);
			if(received != 0) {
				ws_frame_t msg;
				r = ws_process_frame(&msg, (char*)buf, received);

				wsu_dump_frame(&msg);
				free(msg.data.base);
			}
		}
	}

	cleanup:
	free(d.base);
	tcpclose(sock);
}

int main(int argc, char** argv) {
	int port = 8000;
	if(argc > 1) {
		port = atoi(argv[1]);
	}

	ipaddr addr = iplocal(0, port, 0);
	tcpsock tcp = tcplisten(addr, 10);
	if(!tcp) {
		fprintf(stderr, "Failed to bind to port %d (errno %d)\n", port, errno);
		return 1;
	}

	while(1) {
		tcpsock sock = tcpaccept(tcp, -1);
		if(!sock) {
			fprintf(stderr, "Connection lost (errno %d)\n", errno);
			continue;
		}

		go(client(sock));
	}

	return 0;
}
