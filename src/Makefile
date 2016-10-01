CC = gcc
CPPFLAGS =
CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2
CFLAGS += `pkg-config --cflags --libs glib-2.0`
LDFLAGS =
LOADLIBES =
LDLIBS =

SERVER_PORT = 12345
SERVER_PORT ?= $(/labs/tsam15/my_port)

.DEFAULT: all
.PHONY: all post clean

all: httpd

clean:
	rm -f *.o

distclean: clean
	rm -f httpd

post:
	@curl localhost:$(SERVER_PORT)

zip:
	cd ..; zip httpd.zip README src/httpd.c src/Makefile AUTHORS
