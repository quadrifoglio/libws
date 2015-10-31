# libws

Basic C implementation of [RFC6455](https://tools.ietf.org/html/rfc6455).

## Usage

When receiving the first message from a client connection, process the WebSocket handshake.

```c
ws_handshake_t h;
int err = ws_process_handshake(&h, data, length);

if(err) {
	// Handle error
}
else {
	printf("Client connected to URL \"%s\" from origin \"%s\"\n", h.url, h.origin);

	ws_data_t response = ws_handshake_response(&h);
	// Send the response data (response.base, response.len)
}

ws_handshake_done(&h);
```

If the handshake was successful, process the next segments as WebSocket frames.

```c
ws_data_t msg;
int err = ws_process_frame(&msg, data, length);

if(err) {
	// Handle error
}
else {
	// Use the frame data (msg.base, msg.len)
}

free(msg.base);
```

To send a WebSocket message, do the following:

```c
char* data = "Hello WebSocket Client !";
ws_data_t frame = ws_create_frame(WS_FRAME_TEXT, data, strlen(data));

// Then send the frame to the connection (frame.base, frame.len).
```
