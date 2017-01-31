#include <stdio.h>			// printf
#include <string.h>			// strlen
#include <stdlib.h>			// malloc
#include <sys/socket.h>		// socket
#include <arpa/inet.h>		// inet_addr
#include <pcre.h>

#define MSG_SZ 1024
#define OVC_SZ 15


pcre *re_keyval;
int ovc[OVC_SZ];
const char *err;

#include "conf.h"


int process_msg( char *msg, int len ) {
	int res, re_offset = 0;

	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	while ( res == 3 ) {
		*(msg+ovc[3]) = 0;
		*(msg+ovc[5]) = 0;
		printf( "%s -> %s\n", msg+ovc[2], msg+ovc[4] );
		re_offset = ovc[1];
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}
	printf( "#\n# === Received %d bytes ===\n#\n", len );
	return 0;
}

int main( int argc, char **argv ){
	int sock, res, len;
	struct sockaddr_in srv;
	unsigned short buf_offset = 0;
	char *msg, *buf_start, *buf_end;
	conf_t *cfg;
	
	// read config
	cfg = malloc( sizeof( conf_t ) );
	cfg->host = 0x7f000001; // 127.0.0.1
	cfg->port = 5038;
	strcpy( cfg->user, "ampere" );
	strcpy( cfg->pass, "ampere" );
	res = conf_load( cfg );
	if ( res < 0 ) {
		return res;
	}

	// create socket
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock < 0 ) {
		fprintf( stderr, "FATAL: Could not create socket\n" );
		return -2;
	}
	srv.sin_addr.s_addr = cfg->host;
	srv.sin_family = AF_INET;
	srv.sin_port = htons( cfg->port );
	
	// connect to AMI
	res = connect( sock, ( struct sockaddr* ) &srv, sizeof( srv ) );
	if ( res < 0 ) {
		fprintf( stderr, "ERROR: Cannot connect to remote server\n" );
		shutdown( sock, SHUT_RDWR );
		return -1;
	}
	
	msg = malloc( MSG_SZ * 2 );
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\nActionID: amperelogin\r\n\r\n", cfg->user, cfg->pass );
	
	// send AUTH message
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		shutdown( sock, SHUT_RDWR );
		return -2;
	}

	// init REGEXP parser
	re_keyval = pcre_compile( "(.*): (.*)\r\n", 0, &err, &res, NULL );
	if ( !re_keyval ) {
		printf( "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		shutdown( sock, SHUT_RDWR );
		return -2;
	}
	
	printf( "#\n# === Session opened ===\n#\n" );
	while ( 1 ) { // mainloop
		if ( buf_offset < MSG_SZ ) {
			len = recv( sock, msg + buf_offset, MSG_SZ, 0 );
			if ( len < 0 ) {
				fprintf( stderr, "FATAL: Error reciving data\n" );
				shutdown( sock, SHUT_RDWR );
				return -2;
			}
			if ( len > 0 ) {
				*(msg+buf_offset+len) = 0; // set NULLTERM to message end
				buf_start = msg;
				buf_end = strstr( buf_start, "\r\n\r\n" );
				if ( !buf_end ) { // MSGTERM not found, keep buffering
					buf_offset += len;
					continue;
				}
				while ( buf_end ) {
					buf_end += 2; // grab first CRLF
					*buf_end = 0;
					res = process_msg( buf_start, (int)( buf_end - buf_start ) );
					if ( res < 0 ) {
						goto break_mainloop;
					}
					buf_start = buf_end + 2;
					buf_end = strstr( buf_start, "\r\n\r\n" );
				}
				
				if ( msg + buf_offset + len == buf_start ) { // MSGTERM found at the end of message, reset buf_offset
					buf_offset = 0;
				} else { // MSGTERM not found at the end of message, move remain buffer to 0-position
					buf_offset = msg + buf_offset + len - buf_start;
					memcpy( msg, buf_start, buf_offset );
				}
			}
		} else {
			fprintf( stderr, "WARNING: Buffer too large: %d\n", buf_offset );
			buf_offset = 0;
		}
	}
	break_mainloop:;
	
	printf( "#\n# === Session closed ===\n#\n" );

	shutdown( sock, SHUT_RDWR );
	return 0;
}
