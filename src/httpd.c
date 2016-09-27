#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>

int main(int argc, char *argv[]) {
	int sockfd;
    struct sockaddr_in server, client;
    char message[512];
    int port_number = strtol(argv[1], NULL, 10);

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values. */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port_number);
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    /* Before the server can accept messages, it has to listen to the
       welcome port. A backlog of one connection is allowed. */
    listen(sockfd, 1);

	fd_set rfds;
	for(;;) {
		struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		int retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
		if (retval > 0) {
			FD_ISSET(sockfd, &rfds);
			/* We first have to accept a TCP connection, connfd is a fresh handle dedicated to this connection. */
			socklen_t len = (socklen_t) sizeof(client);
			int connfd = accept(sockfd, (struct sockaddr *) &client, &len);
			/* Receive from connfd, not sockfd. */
			ssize_t n = recv(connfd, message, sizeof(message) - 1, 0);

			message[n] = '\0';

			fprintf(stdout, "Recieved:\n%s\n", message);

			GString* response = g_string_new("http/1.1 404 NOT FOUND\r\n\r\n<h1>Not found</h1>");

			send(connfd, response->str, (size_t)response->len, 0);
		}
		else {
			printf("No connection in 5 seconds\n");
		}
	}
}