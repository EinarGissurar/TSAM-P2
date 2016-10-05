CC = gcc
CPPFLAGS =
CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2
CFLAGS += `pkg-config --cflags --libs glib-2.0`
LDFLAGS =
LOADLIBES =
LDLIBS =
SHELL := /bin/bash

SERVER_PORT := 12345

# if "/labs/tsam15/my_port" exists
ifeq (,$(wildcard /labs/tsam15/my_port))
	#SERVER_PORT := $(/labs/tsam15/my_port)
endif

.DEFAULT: all
.PHONY: all post clean

all: httpd

clean:
	rm -f *.o

distclean: clean
	rm -f httpd

run:
	./httpd $(SERVER_PORT)

post:
	@curl localhost:$(SERVER_PORT) --data "post request data"

zip:
	cd ..; zip httpd.zip README src/httpd.c src/Makefile AUTHORS
