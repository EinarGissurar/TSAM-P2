/*
 * Programming Assignment 2 – httpd
 *
 * Team:
 * Einar Örn Gissurarson <einarog05@ru.is>
 * Óskar Örn <oskart10@ru.is>
 * Peter Hostačný <peterh16@ru.is>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h> // inet_ntoa
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <glib.h>

#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif


// COOKIES IMPLEMENT BY USING HASH TABLE
// https://developer.gnome.org/glib/stable/glib-Hash-Tables.html

// HEADERS STORE BY USING KEYED DATA LIST
// https://developer.gnome.org/glib/stable/glib-Keyed-Data-Lists.html

// TIMER FOR CONNECTIONS WHAT REQUESTED "KEEP-ALIVE"
// https://developer.gnome.org/glib/stable/glib-Timers.html

// RANDOM NUMBERS (maybe for implementing fairness ?)
// https://developer.gnome.org/glib/stable/glib-Random-Numbers.html

// DATE & TIME for log file
// https://developer.gnome.org/glib/stable/glib-Date-and-Time-Functions.html

// DOUBLE ENDED QUEUES for storing CLIENTS FILE DESCRIPTORS TOGETHER WITH TIMER FOR EACH FD (so it will be possible to iterate through them)
// https://developer.gnome.org/glib/stable/glib-Double-ended-Queues.html

// STRING FOR MESSAGES (don't need to think about buffers of fixed length anymore)
// https://developer.gnome.org/glib/stable/glib-Strings.html
// https://developer.gnome.org/glib/stable/glib-String-Utility-Functions.html


// some useful links:
// - glibc working with lists, iterators, etc.: https://www.ibm.com/developerworks/linux/tutorials/l-glib/
// - more human friendly explaining HTTP:
// https://www.tutorialspoint.com/http/http_responses.htm
// https://www.tutorialspoint.com/http/http_header_fields.htm
// - how select works: http://www.binarytides.com/multiple-socket-connections-fdset-select-linux/


typedef struct ClientConnection {
	int conn_fd;
	GTimer *conn_timer;
} ClientConnection;


FILE *log_file = NULL;
int sockfd; // master socket
GQueue *clients_queue;


/* Destroy/close/free instance of ClientConnection.
   @connection has to be allocated by malloc() */
void destroy_ClientConnection(ClientConnection *connection) {
	close(connection->conn_fd); // close socket with client connection
	if (connection->conn_timer != NULL)
		g_timer_destroy(connection->conn_timer); // destroy timer, if any
	free(connection); // free memory allocated for this instance of ClientConnection
}

void remove_ClientConnection(ClientConnection *connection) {
	destroy_ClientConnection(connection);
	if (!g_queue_remove(clients_queue, connection)) {
		printf("Something is wrong. Connection was not found in queue.\n");
	}
}

void destroy_clients_queue(GQueue *clients_queue) {
	g_queue_foreach(clients_queue, (GFunc) remove_ClientConnection, NULL);
	g_queue_free(clients_queue);
}


void clean_and_die() {

	/* Close the connections. */
	// http://stackoverflow.com/questions/4160347/close-vs-shutdown-socket
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);

	fclose(log_file);

	int num_of_connections = clients_queue->length;

	destroy_clients_queue(clients_queue);
	clients_queue = NULL;

	printf("%d connections closed.\n", num_of_connections);

	exit(0);
}


// Signal handler function.
void sig_handler(int signal_n) {
	if (signal_n == SIGINT) {
		printf("\nShutting down...\n");
	}
	clean_and_die();
}


/* Function for printing messages into log file. */
void log_msg(char *msg) {
	fprintf(log_file, "%s", msg);
	fflush(log_file);
	return;
}


void new_client(int conn_fd) {
	ClientConnection *connection = g_new0(ClientConnection, 1);
	connection->conn_fd = conn_fd;
	g_queue_push_tail(clients_queue, connection);
}


//add child socket to set
void add_socket_into_set(ClientConnection *connection, fd_set *readfds_ptr) {
	FD_SET(connection->conn_fd, readfds_ptr);
}

void max_sockfd(ClientConnection *connection, int *max) {
	*max = max(connection->conn_fd, *max);
}


int return_max_sockfd_in_queue(GQueue *clients_queue) {
	int max = 0;
	g_queue_foreach(clients_queue, (GFunc) max_sockfd, &max);
	return max;
}



void handle_connection(ClientConnection *connection) {

	char buffer[1024];
	int connection_close = FALSE;

	/* TODO */
	// implement recv in loop - count with case that request is larger than buffer
	// call recv more times if it is neccessary and store message into some dynamic variable (string)
	// parse http headers to some dictionary

	ssize_t n = recv(connection->conn_fd, buffer, sizeof(buffer) - 1, 0);

	buffer[n] = '\0';

	fprintf(stdout, "Received:\n%s\n", buffer);

	// TODO
	// Add header: "Content-Type: text/html; charset=utf-8"

	// TODO
	// Add header with date and time (example: "Date: Tue, 15 Nov 1994 08:12:31 GMT")
	// https://tools.ietf.org/html/rfc7231#page-65

	/* TODO */
	// PARSE HEADERS
	// if there is header "Connection: keep-alive" start timer at the end of this function before returning
	// if there is header "Connection: keep-alive" in request, return it also in response
	// In HTTP 1.1, all connections are considered persistent unless declared otherwise.

	GString* headers = g_string_new("HTTP/1.1 200 OK\r\n");
	// TODO
	// generate body here (create function for it) according to assignment
	GString* body = g_string_new("something");
	//g_string_append(response, "");

	GString *response = headers;
	g_string_append(response, "\r\n");
	g_string_append(response, body->str);

	g_string_append_printf(headers, "Content-Length: %lu", body->len);


	// TODO
	// IF THERE IS A HEADER "Connection: close", add this header also to response
	if (FALSE) { // change condition after parsing headers
		// add header to the response
		connection_close = TRUE;
	}

	// TODO
	// maybe reset timer if connection is persistent (question is in which case we should reset timer - rfc ?)

	send(connection->conn_fd, response->str, (size_t)response->len, 0);

	g_string_free(headers, TRUE);
	g_string_free(body, TRUE);

	// remove this after implementation of Connection: close
	remove_ClientConnection(connection);

	if (connection_close) {
		remove_ClientConnection(connection);
	}

	return;
}

/* check if socket is in the set of waiting sockets and handle connection if it is */
void handle_socket_if_waiting(ClientConnection *connection, fd_set *readfds) {

	if (FD_ISSET(connection->conn_fd, readfds)) {
		handle_connection(connection);
	}
}


void run_loop() {
	struct sockaddr_in client;
	int max_sockfd;

	fd_set readfds;
	while(42) {
		struct timeval tv;
		// every second check all timers - for purposes of handling keep-alive duration (30s)
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		//clear the socket set
		FD_ZERO(&readfds);

		//add master socket to set
		FD_SET(sockfd, &readfds);
		max_sockfd = max(sockfd, return_max_sockfd_in_queue(clients_queue));

		//add child sockets to set
		g_queue_foreach(clients_queue, (GFunc) add_socket_into_set, &readfds);

		int retval = select(max_sockfd + 1, &readfds, NULL, NULL, &tv);
		if (retval < 0) {
			perror("select error");
			return;

		}
		else if (retval == 0) {// timeout
			// TODO
			// check all client's timers, if any of them exceeded 30 seconds, close the connection and destroy/remove record from clients_queue
			continue;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			//If something happened on the master socket , then its an incoming connection
			socklen_t len = (socklen_t) sizeof(client);
			// accept new client
			int conn_fd = accept(sockfd, (struct sockaddr *) &client, &len);

			//add new client into the queue
			new_client(conn_fd);

			printf("New connection , socket fd is %d , ip is : %s , port : %d \n",
					conn_fd, inet_ntoa(client.sin_addr), ntohs(client.sin_port));

			handle_connection(g_queue_peek_tail(clients_queue));
		}

		g_queue_foreach(clients_queue, (GFunc) handle_socket_if_waiting, &readfds);

		// TODO check timers also here

	}

}



int main(int argc, char *argv[]) {

	struct sockaddr_in server;
	int port_number = strtol(argv[1], NULL, 10);

	// checking the number of arguments
	if (argc != 2) {
		printf("Usage: %s <port>\n", argv[0]);
		return 1;
	}

	log_file = fopen("httpd.log","a");
	if (log_file == NULL) {
		perror("creating/opening of logfile failed");
		return EXIT_FAILURE;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		printf("\nCannot catch SIGINT!\n");

	// create queue for storing client connections
	clients_queue = g_queue_new();

	/* Create and bind a TCP socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == 0) {
		perror("socket() failed");
		return EXIT_FAILURE;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
    	perror("setsockopt(SO_REUSEADDR) failed");

	/* Network functions need arguments in network byte order instead of
	   host byte order. The macros htonl, htons convert the values. */
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port_number);

	if (bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server)) < 0) {
		perror("bind() failed");
		return EXIT_FAILURE;
	}

	/* Before the server can accept messages, it has to listen to the
	   welcome port.*/
	printf("Listening on port %d \n", port_number);
	listen(sockfd, 10);
	printf("Waiting for connections ...\n");

	run_loop();

	clean_and_die();

}
