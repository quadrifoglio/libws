#include <uv.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "libws.h"

typedef struct {
	bool accepted;
} client_t;

static uv_loop_t* loop;

void on_alloc(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
	buf->base = malloc(size);
	buf->len = size;
}

void on_close(uv_handle_t* handle) {
	free(handle->data);
	free(handle);
}

void on_write(uv_write_t* w, int status) {
	if(status < 0) {
		uv_close((uv_handle_t*)w->handle, on_close);
	}

	free(w);
}

void on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
	if(nread >= 0) {
		client_t* c = (client_t*)handle->data;

		if(!c->accepted) {
			ws_handshake_t h;
			int r = ws_process_handshake(&h, buf->base, nread);

			if(r) {
				fprintf(stderr, "ws: %s\n", ws_err_name(r));
				uv_close((uv_handle_t*)handle, on_close);
			}
			else {
				c->accepted = true;
				char* resp = ws_handshake_response(&h);

				uv_write_t* w = (uv_write_t*)malloc(sizeof(uv_write_t));
				uv_buf_t b = { .base = resp, .len = h.responseSize };

				uv_write(w, handle, &b, 1, on_write);
				ws_handshake_done(&h);
			}
		}
		else {
			ws_data_t data;
			int r = ws_process_frame(&data, buf->base, nread);

			if(r) {
				fprintf(stderr, "ws: %s\n", ws_err_name(r));
				uv_close((uv_handle_t*)handle, on_close);
			}
			else {
				write(1, data.base, data.len);
			}
		}
	}
	else {
		uv_close((uv_handle_t*)handle, on_close);
	}

	free(buf->base);
}

void on_connect(uv_stream_t* serv, int status) {
	if(status < 0) {
		fprintf(stderr, "on_connect: %s\n", uv_err_name(status));
		return;
	}

	uv_tcp_t* handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	handle->data = (client_t*)malloc(sizeof(client_t));

	int r = uv_tcp_init(loop, handle);
	if(r) {
		fprintf(stderr, "handle init: %s\n", uv_err_name(r));
		return;
	}

	r = uv_accept(serv, (uv_stream_t*)handle);
	if(r) {
		fprintf(stderr, "accept: %s\n", uv_err_name(r));
		return;
	}

	r = uv_read_start((uv_stream_t*)handle, on_alloc, on_read);
	if(r) {
		fprintf(stderr, "read_start: %s\n", uv_err_name(r));
		return;
	}
}

int main(void) {
	loop = uv_default_loop();
	uv_tcp_t serv;

	int r = uv_tcp_init(loop, &serv);
	if(r) {
		fprintf(stderr, "init: %s\n", uv_err_name(r));
		return 1;
	}

	struct sockaddr_in addr;
	uv_ip4_addr("0.0.0.0", 8000, &addr);

	r = uv_tcp_bind(&serv, (const struct sockaddr_in*)&addr, 0);
	if(r) {
		fprintf(stderr, "bind: %s\n", uv_err_name(r));
		return 1;
	}

	r = uv_listen((uv_stream_t*)&serv, 2, on_connect);
	if(r) {
		fprintf(stderr, "listen: %s\n", uv_err_name(r));
		return 1;
	}

	uv_run(loop, UV_RUN_DEFAULT);
	return 0;
}
