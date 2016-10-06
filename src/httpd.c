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
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include <stdbool.h>
#include <time.h>

#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#define KEEP_ALIVE_TIMEOUT 30


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

typedef enum HttpMethod {GET, HEAD, POST, UNKNOWN} HttpMethod;

const char * const http_methods[] = {
	"GET",
	"HEAD",
	"POST",
	"UNKNOWN",
};

typedef struct ClientConnection {
	int conn_fd;
	GTimer *conn_timer;
	int request_count;
	struct sockaddr_in client_sockaddr;
	GString *cookie_token;
} ClientConnection;


typedef struct Request {
	HttpMethod method;
	GString *host;
	GString *path;
	GString *path_without_query;
	GString *query;
	GString *message_body;
	bool connection_close;
	GHashTable* headers;
} Request;


/***  GLOBAL VARIABLES  ***/
FILE *log_file = NULL;
int sockfd; // master socket
GQueue *clients_queue;
GHashTable* cookies;
int cookie_cnt = 0;

/* Initialize structure */
void init_Request(Request *request) {
	request->host = g_string_new(NULL);
	request->path = g_string_new(NULL);
	request->path_without_query = g_string_new(NULL);
	request->query = g_string_new(NULL);
	request->message_body = g_string_new(NULL);
	request->connection_close = false;
	request->method = UNKNOWN;
	request->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

/* Free memory allocated for items in structure Request. */
void destroy_Request(Request *request) {
	g_string_free(request->host, TRUE);
	g_string_free(request->path, TRUE);
	g_string_free(request->path_without_query, TRUE);
	g_string_free(request->query, TRUE);
	g_string_free(request->message_body, TRUE);
	g_hash_table_destroy(request->headers);
}

void print_header(gchar *key, gchar *value, GString *destination) {
	g_string_append_printf(destination, "[%s] : [%s]<br/>\n", key, value);
}


/* Destroy/close/free instance of ClientConnection.
   @connection has to be allocated by malloc() */
void destroy_ClientConnection(ClientConnection *connection) {

	printf("Closing connection %s:%d (fd:%d)\n", inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), connection->conn_fd);

	close(connection->conn_fd); // close socket with client connection
	g_timer_destroy(connection->conn_timer); // destroy timer
	g_string_free(connection->cookie_token, TRUE);
	g_free(connection); // free memory allocated for this instance of ClientConnection
}

/* Takes a connection from the queue and runs destroy_ClientConnection function */
void remove_ClientConnection(ClientConnection *connection) {
	destroy_ClientConnection(connection);
	if (!g_queue_remove(clients_queue, connection)) {
		printf("Something is wrong. Connection was not found in queue.\n");
	}
}

/* Runs through the queue of clients and runs remove_ClientConnection for every instance in it,
   then frees the memory */
void destroy_clients_queue(GQueue *clients_queue) {
	g_queue_foreach(clients_queue, (GFunc) remove_ClientConnection, NULL);
	g_queue_free(clients_queue);
}

/* Closes the connection of both socket and file writer, runs destroy_clients_queue function and exits program */
void clean_and_die(int exit_code) {

	/* Close the connections. */
	// http://stackoverflow.com/questions/4160347/close-vs-shutdown-socket
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);

	fclose(log_file);

	printf("Closing %d connections.\n", clients_queue->length);

	destroy_clients_queue(clients_queue);
	clients_queue = NULL;

	g_hash_table_destroy(cookies);

	exit(exit_code);
}

/* Signal handler function that closes down program, by running clean_and_die function */
void sig_handler(int signal_n) {
	if (signal_n == SIGINT) {
		printf("\nShutting down...\n");
	}
	clean_and_die(0);
}

/* Function for printing messages into log file. */
void log_msg(Request *request) {

	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char iso_8601[] = "YYYY-MM-DDThh:mm:ssTZD";
	strftime(iso_8601, sizeof iso_8601, "%FT%T%Z", now_tm);


	GString *log_msg = g_string_new(iso_8601);
	g_string_append_printf(log_msg, " : %s %s %s : InsertResponseCodeHere \n", request->host->str, http_methods[request->method], request->path->str);

	fprintf(log_file, "%s", log_msg->str); // print log message to log file
	fflush(log_file);
	g_string_free(log_msg, TRUE); // free memory

	return;
}

/*  Random string generator */
void random_string(char *string, size_t length)
{
	static char charset[] = "0123456789"
				"abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/* Seed number for rand() */
	srand((unsigned int) time(0));

	while (length-- > 0) {
		size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
		*string++ = charset[index];
	}

	*string = '\0';
}

bool check_cookie_in_headers(Request *request, ClientConnection *connection) {

	bool cookie_found = false;
	gchar *cookie_header_value = g_hash_table_lookup(request->headers, "cookie");

	// if there was header Cookie
	if (cookie_header_value) {
		gchar **cookies_splitted = g_strsplit_set(cookie_header_value, ";", 0);
		for (unsigned int i = 0; i < g_strv_length(cookies_splitted); i++) {
			gchar **cookie = g_strsplit_set(cookies_splitted[i], "=", 2);
			if (g_strv_length(cookie) == 2) {
				g_strstrip(cookie[0]);
				g_strstrip(cookie[1]);
				if (g_strcmp0(cookie[0], "sessionToken") == 0) {
					printf("CLIENT SENT COOKIE: [%s]\n", cookie[1]);
					printf("GOING TO LOOK IT UP\n");
					if (g_hash_table_lookup(cookies, cookie[1])) {
						g_string_assign(connection->cookie_token, cookie[1]);
						printf("COOKIE FOUND IN HASH_TABLE, ASSIGNED TO CONNECTION\n");
						cookie_found = true;
					}
				}
			}
			g_strfreev(cookie);
		}
		g_strfreev(cookies_splitted);
	}
	return cookie_found;
}


/* When a new client wishes to establish a connection, we create the connection and add it to the queue */
void new_client(int conn_fd) {
	ClientConnection *connection = g_new0(ClientConnection, 1);
	// find out client IP and port
	int addrlen = sizeof(connection->client_sockaddr);
	getpeername(conn_fd, (struct sockaddr*)&(connection->client_sockaddr), (socklen_t*)&addrlen);

	connection->conn_fd = conn_fd;
	connection->request_count = 0;
	connection->conn_timer = g_timer_new();
	connection->cookie_token = g_string_new(NULL);
	g_queue_push_tail(clients_queue, connection);
}

/* Add child socket to set */
void add_socket_into_set(ClientConnection *connection, fd_set *readfds_ptr) {
	FD_SET(connection->conn_fd, readfds_ptr);
}

/* A helper function to find the connection with highest sockfd */
void max_sockfd(ClientConnection *connection, int *max) {
	*max = max(connection->conn_fd, *max);
}

/* Runs max_sockfd for every client in queue and returns the higest value */
int return_max_sockfd_in_queue(GQueue *clients_queue) {
	int max = 0;
	g_queue_foreach(clients_queue, (GFunc) max_sockfd, &max);
	return max;
}

/* Check timer of the connection and close/destroy connection if time exceeded KEEP_ALIVE_TIMEOUT seconds */
void check_timer(ClientConnection *connection) {

	gdouble seconds_elapsed = g_timer_elapsed(connection->conn_timer, NULL);

	if (seconds_elapsed >= KEEP_ALIVE_TIMEOUT) {
		printf("[TIMEOUT] ");
		destroy_ClientConnection(connection);
		if (!g_queue_remove(clients_queue, connection)) {
			printf("Something is wrong. Connection was not found in queue.\n");
		}
	}
}

/* Receive whole packet from socket.
   Store data into @message (actual content of message will be discarded) */
bool receive_whole_message(int conn_fd, GString *message) {

	const ssize_t BUFFER_SIZE = 1024;
	ssize_t n = 0;
	char buffer[BUFFER_SIZE];
	g_string_truncate (message, 0); // empty provided GString variable

	do {
		n = recv(conn_fd, buffer, BUFFER_SIZE - 1, 0);
		if (n == -1) { // error while recv()
			perror("recv error");
		}
		else if (n == 0) {
			printf("Client was disconnected.\n");
			return false;
		}
		buffer[n] = '\0';
		g_string_append_len(message, buffer, n);
	} while(n > 0 && n == BUFFER_SIZE - 1);

	return true;
}

/* Uses the data in Request to build a HTML page, to be returned into body */
GString *create_html_page(Request *request, ClientConnection *connection) {

	bool show_query = false;
	bool show_empty_page = false;
	bool show_headers = false;

	GString *html_page = g_string_new("<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Test page.</title>\n</head>\n<body");

	// special page /colour
	if (g_strcmp0(request->path_without_query->str, "/test/colour") == 0) {
		show_empty_page = true;
		if(request->query->len > 0 && g_str_has_prefix(request->query->str, "bg=")) {
			g_string_append_printf(html_page, " style=\"background-color:%s\"", request->query->str+3);

			// cookie was not provided by client or is wrong
			if (connection->cookie_token->len == 0) {
				char token[16];
				random_string(token, 16);
				g_string_assign(connection->cookie_token, token);
				printf("NEW COOKIE GENERATED: [%s]\n", token);
			}
			// create/rewrite value (background color for this client)
			g_hash_table_insert(cookies, g_strdup(connection->cookie_token->str), g_strdup(request->query->str+3));
			printf("NEW VALUE INSERTED INTO HASH TABLE: [%s]\n", connection->cookie_token->str);
		}
		else if (connection->cookie_token->len > 0) { // correct cookie was provided in the request

			gchar *color = g_hash_table_lookup(cookies, connection->cookie_token->str);
			g_string_append_printf(html_page, " style=\"background-color:%s\"", color);
		}
	}
	g_string_append(html_page, ">\n");

	// special page /test
	if (g_strcmp0(request->path_without_query->str, "/test/query") == 0 && request->query->len > 0) {
		show_query = true;
	}

	if (g_strcmp0(request->path_without_query->str, "/test/headers") == 0) {
		show_headers = true;
	}

	if (!show_empty_page) {
		if (request->method == UNKNOWN) {
			g_string_append(html_page, "Unknown method");
		}
		else {
			GString *path_to_display;
			if (show_query)
				path_to_display = request->path_without_query;
			else
				path_to_display = request->path;

			g_string_append_printf(html_page, "http://%s%s %s:%d<br/>\n", request->host->str, path_to_display->str,
				inet_ntoa(connection->client_sockaddr.sin_addr), ntohs(connection->client_sockaddr.sin_port));
			if (request->method == POST) {
				g_string_append_printf(html_page, "%s<br/>\n", request->message_body->str);
			}
			if (show_query) {
				g_string_append_printf(html_page, "%s<br/>\n", request->query->str);
			}
			if (show_headers) {
				g_hash_table_foreach(request->headers, (GHFunc)print_header, html_page);
			}
		}
	}

	g_string_append(html_page, "\n</body>\n</html>");

	return html_page;
}


/* Uses the data that was fetched in recieve_whole_message and parses it into a Request */
bool parse_request(GString *received_message, Request *request) {

	bool default_persistent = true;

	// parsing METHOD
	if (g_str_has_prefix(received_message->str, "GET")) {
		request->method = GET;
	}
	else if (g_str_has_prefix(received_message->str, "HEAD")) {
		request->method = HEAD;
	}
	else if (g_str_has_prefix(received_message->str, "POST")) {
		request->method = POST;
	}
	else {
		request->method = UNKNOWN;
		printf("Unknown method in request. Connection will be closed.\n");
		return false;
	}

	// parsing PATH
	gchar **request_line = g_strsplit(received_message->str, " ", 3);
	if (g_strv_length(request_line) < 3) {
		g_strfreev(request_line);
		printf("Request cannot be parsed. Connection will be closed.\n");
		return false;
	}
	g_string_assign(request->path, request_line[1]);
	if (g_strcmp0(request_line[2], "HTTP/1.0")) {
		default_persistent = false;
	}
	g_strfreev(request_line);

	// parsing http request MESSAGE BODY
	gchar *message_body = g_strstr_len(received_message->str, received_message->len, "\r\n\r\n");
	int headers_length = message_body - received_message->str;
	if (message_body == NULL) {
		printf("Request cannot be parsed. Connection will be closed.\n");
		return false;
	}
	else {
		message_body += 4; // "\r\n\r\n"
	}
	g_string_assign(request->message_body, message_body);

	// parse query from path
	gchar *start_of_query = g_strstr_len(request->path->str, request->path->len, "?");
	if (start_of_query != NULL) {
		g_string_truncate(request->path_without_query, 0);
		g_string_append_len(request->path_without_query, request->path->str, start_of_query - request->path->str);
		g_string_assign(request->query, start_of_query+1);
		gchar *end_of_query = g_strstr_len(request->query->str, request->query->len, "#");
		if (end_of_query != NULL) {
			g_string_truncate(request->query, end_of_query - request->query->str);
		}
	}
	else
		g_string_assign(request->path_without_query, request->path->str);

	// truncate message body so only headers will left
	g_string_truncate(received_message, headers_length);

	// split message to headers
	gchar *start_of_headers = g_strstr_len(received_message->str, received_message->len, "\r\n");
	gchar **headers_arr = g_strsplit_set(start_of_headers, "\r\n", 0);

	// for each header line
	for (unsigned int i = 0; i < g_strv_length(headers_arr); i++) {

		// headers can also contains empty lines because "\r\n" are understood as two delimiters in split command
		if (strlen(headers_arr[i]) == 0)
			continue;

		gchar **header_line = g_strsplit_set(headers_arr[i], ":", 2);
		if (g_strv_length(header_line) != 2) {
			printf("WRONG FORMAT OF HEADER\n");
			g_strfreev(headers_arr);
			g_strfreev(header_line);
			return false;
		}

		gchar *header_name = g_ascii_strdown(header_line[0], -1); // convert to lowercase (arg. -1 if string is NULL terminated)
		gchar *header_value = g_strdup(header_line[1]);
		g_strstrip(header_value); // strip leading and trailing whitespaces
		g_strfreev(header_line); // free splitted line

		g_hash_table_insert(request->headers, header_name, header_value);
		// gchar *value = g_hash_table_lookup(hash_table, "key")
		// g_free(gchar *pointer);

		if (g_strcmp0(header_name, "host") == 0) {
			g_string_assign(request->host, header_value);
		}
		if (g_strcmp0(header_name, "connection") == 0) {
			if (g_strcmp0(header_value, "close") == 0)
				request->connection_close = true;
			if (!default_persistent && g_strcmp0(header_value, "keep-alive") != 0)
				request->connection_close = true;
		}
	}

	if (request->host == NULL) {
		printf("\"Host:\" header not found. Connection will be closed.\n");
		g_strfreev(headers_arr);
		return false;
	}
	g_strfreev(headers_arr);

	return true;
}


/* Processes the request of client and builds a response,
   using recieve_whole_message, parse_request, create_html_page and log_msg */
void handle_connection(ClientConnection *connection) {

	Request request;
	init_Request(&request);
	GString *response = g_string_sized_new(1024);
	bool set_cookie = false;

	// print out client IP and port
	printf("Serving client %s:%d (fd:%d)\n", inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), connection->conn_fd);

	// Receiving packet from socket
	GString *received_message = g_string_sized_new(1024);
	if (!receive_whole_message(connection->conn_fd, received_message)) {
		request.connection_close = TRUE;
		goto exit_handling; // message was not received or has length 0
	}
	fprintf(stdout, "Received:\n%s\n", received_message->str);

	// parse request
	if (!parse_request(received_message, &request)) {
		request.connection_close = TRUE;
		goto exit_handling; // message was not received or has length 0
	}

	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char date_and_time[512];
	strftime(date_and_time, sizeof date_and_time, "%a, %d %b %Y %H:%M:%S %Z", now_tm);

	g_string_append(response, "HTTP/1.1 200 OK\r\n");
	g_string_append(response, "Content-Type: text/html; charset=utf-8\r\n");
	// https://tools.ietf.org/html/rfc7231#page-65
	g_string_append_printf(response, "Date: %s\r\n", date_and_time); // example: "Date: Tue, 15 Nov 1994 08:12:31 GMT"

	connection->request_count++; // increment counter of requests per connection
	if (!request.connection_close && connection->request_count < 100) {
		g_timer_start(connection->conn_timer); // reset timer
		// In HTTP 1.1, all connections are considered persistent unless declared otherwise.
		g_string_append(response, "Connection: keep-alive\r\n");
		g_string_append_printf(response, "Keep-Alive: timeout=%d, max=100\r\n", KEEP_ALIVE_TIMEOUT);
	}
	else {
		request.connection_close = TRUE; // in case request_count is >= 100
		g_string_append(response, "Connection: close\r\n");
	}

	if (!check_cookie_in_headers(&request, connection)) {
		set_cookie = true; // cookie sent by client is not valid or client didn't send any
	}

	GString *message_body = create_html_page(&request, connection);
	g_string_append_printf(response, "Content-Length: %lu\r\n", message_body->len);

	if (set_cookie && connection->cookie_token->len > 0) {
		g_string_append_printf(response, "Set-Cookie: sessionToken=%s\r\n", connection->cookie_token->str);
	}

	g_string_append(response, "\r\n"); // newline separating headers and message body


	if (request.method != HEAD) {
		g_string_append(response, message_body->str); // appending message body to the end of response
	}

	g_string_free(message_body, TRUE);

	send(connection->conn_fd, response->str, response->len, 0);

	log_msg(&request); // make a record to log file


exit_handling:
	g_string_free(received_message, TRUE);
	g_string_free(response, TRUE);
	destroy_Request(&request);
	if (request.connection_close) {
		remove_ClientConnection(connection);
	}
	printf("\n"); // empty line

	return;
}

/* check if socket is in the set of waiting sockets and handle connection if it is */
void handle_socket_if_waiting(ClientConnection *connection, fd_set *readfds) {

	if (FD_ISSET(connection->conn_fd, readfds)) {
		handle_connection(connection);
	}
}

/* A looping function that waits for incoming connection, adds it
   to the queue and attempts to processes all clients waiting in the queue */
void run_loop() {
	struct sockaddr_in client;
	int max_sockfd;

	cookies = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	fd_set readfds;
	while(42) {
		struct timeval tv;
		// every second check all timers - for purposes of handling keep-alive timeout
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
		else if (retval == 0) { // timeout
			g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);
			continue;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			//If something happened on the master socket , then its an incoming connection
			socklen_t len = (socklen_t) sizeof(client);
			// accept new client
			int conn_fd = accept(sockfd, (struct sockaddr *) &client, &len);

			//add new client into the queue
			new_client(conn_fd);

			printf("New connection: %s:%d (socket: %d )\n",
					inet_ntoa(client.sin_addr), ntohs(client.sin_port), conn_fd);

			handle_connection(g_queue_peek_tail(clients_queue));
		}

		g_queue_foreach(clients_queue, (GFunc) handle_socket_if_waiting, &readfds);

		// check timer of every connection in queue
		g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);

	}

}


/* main function */
int main(int argc, char *argv[]) {

	// checking the number of arguments
	if (argc != 2) {
		printf("Usage: %s <port>\n", argv[0]);
		return 1;
	}

	struct sockaddr_in server;
	int port_number = strtol(argv[1], NULL, 10);


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
	printf("Waiting for connections ...\n\n");

	run_loop();

	clean_and_die(0);

}
