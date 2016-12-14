#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "websocket.h"

int main(int argc, char** argv) {
	if(argc < 2) {
		puts("Usage: parrot <port>");
		return 1;
	}

	int port = atoi(argv[1]);
	if(port <= 0) {
		puts("Invalid port number");

		return 1;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		perror("socket");
		return 1;
	}

	int val = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		perror("setsockopt");

		close(sockfd);
		return 1;
	}

	struct sockaddr_in addr = {0};
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");

		close(sockfd);
		return 1;
	}

	if(listen(sockfd, 10) < 0) {
		perror("listen");

		close(sockfd);
		return 1;
	}

	while(1) {
		struct sockaddr_in addr = {0};
		socklen_t len = sizeof(addr);

		int clientfd = accept(sockfd, (struct sockaddr*)&addr, &len);
		if(clientfd < 0) {
			perror("accept");
			continue;
		}

		struct wsStatus status = {0};
		if(!wsHandshake(clientfd, &status)) {
			fputs("Failed to process websocket handshake", stderr);
			continue;
		}

		printf("WebSocket connection on %s using protocol version %d\n", status.url, status.version);

		struct wsMessage msg = {0};
		while(wsRecv(clientfd, &msg)) {
			char* str = calloc(1, msg.len + 1);
			memcpy(str, msg.payload, msg.len);

			puts(str);

			free(str);
			wsMessageFree(&msg);
		}
	}

	close(sockfd);
	return 0;
}
