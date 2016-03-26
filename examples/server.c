#include "ws.h"

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

void client(int csfd) {
	ws_handshake_t h;
	int err = ws_handshake_process(&h, csfd);
	if(err) {
		fputs("process_handshake: failed", stderr);
		goto cleanup;
	}

	ws_data_t response = ws_handshake_response(&h);
	send(csfd, response.base, response.len, 0);

	while(true) {
		ws_frame_t msg;

		int err = ws_frame_process(&msg, csfd);
		if(err) {
			fputs("process_frame: failed", stderr);
			break;
		}

		free(msg.data.base);
	}

cleanup:
	ws_handshake_done(&h);
	shutdown(csfd, SHUT_RDWR);
	close(csfd);
}

void sigint() {
	exit(0);
}

int main(int argc, char** argv) {
	signal(SIGINT, sigint);

	int nproc = 1;
	if(argc > 1) {
		nproc = atoi(argv[1]);
	}

	int sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sockfd == -1) {
		perror("socket");
		return 1;
	}

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(8000);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 0, 0);

	if(bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		perror("bind");
		return 1;
	}

	if(listen(sockfd, 1) != 0) {
		perror("listen");
		return 1;
	}

	while(true) {
		int csfd = accept(sockfd, 0, 0);
		if(csfd == -1) {
			perror("accept");
			continue;
		}

		client(csfd);
	}

	shutdown(sockfd, 2);
	close(sockfd);

	return 0;
}
