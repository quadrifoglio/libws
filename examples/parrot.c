#include <stdio.h>
#include <stdlib.h>

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

	return 0;
}
