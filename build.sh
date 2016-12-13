#!/bin/bash

set -e

cc=gcc
cflags="-Wall -Wextra --std=gnu99 -Iinclude"

ld=gcc
libs="-lm"

cc() {
	$cc $cflags -c $2 -o $1
}

ld() {
	$ld $2 -o $1 $libs
}

mkdir -p bin/examples

cc bin/websocket.o src/websocket.c
cc bin/examples/parrot.o examples/parrot.c

ld bin/examples/parrot "bin/examples/parrot.o bin/websocket.o"
