#include <stdio.h>
#include <stdlib.h>
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

	struct sockaddr_in addr = {0};
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	if(listen(sockfd, 10) < 0) {
		perror("listen");
		return 1;
	}
	
	while(1) {
		struct sockaddr_in addr = {0};
		socklen_t len = sizeof(addr);

		int clientfd = accept(sockfd, (struct sockaddr*)&addr, &len);
		if(clientfd < 0) {
			perror("accept");
			return 1;
		}

		puts("Client connection");
	}

	return 0;
}
