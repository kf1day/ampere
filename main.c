#include <stdio.h>			// printf
#include <string.h>			// strlen
#include <stdlib.h>			// malloc
#include <sys/socket.h>		// socket
#include <arpa/inet.h>		// inet_addr
#include <pcre.h>

#define MSG_SZ 1024
#define OVC_SZ 15

#include "conf.h"


pcre *re_keyval;
int ovc[OVC_SZ];


int process_msg( char *msg, int len ) {
	int res, re_offset = 0;

	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	while ( res == 3 ) {
		*(msg+ovc[3]) = 0;
		*(msg+ovc[5]) = 0;
		printf( "%s == %s\n", msg+ovc[2], msg+ovc[4] );
		re_offset = ovc[1];
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}
	printf( "=== Received %d bytes ===\n", len );
	return 0;
}

int main( int argc, char **argv ){
	int sock, res, len;
	struct sockaddr_in srv;
	unsigned short buf_offset = 0;
	char *msg, *buf_start, *buf_end;
	const char *err;
	
	// create socket
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock < 0 ) {
		fprintf( stderr, "FATAL: Could not create socket\n" );
		return -1;
	}
	
	srv.sin_addr.s_addr = inet_addr( "192.168.0.212" );
	srv.sin_family = AF_INET;
	srv.sin_port = htons( 5038 );
	
	// connect to AMI
	res = connect( sock, ( struct sockaddr* ) &srv, sizeof( srv ) );
	if ( res < 0 ) {
		fprintf( stderr, "ERROR: Cannot connect to remote server\n" );
		return -1;
	}
	
	msg = malloc( MSG_SZ * 2 );
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\nActionID: amperelogin\r\n\r\n", "ampere", "123" ); // \r\nActionID: amperelogin
	
	// send AUTH message
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		return -1;
	}

	// init REGEXP parser
	re_keyval = pcre_compile( "(.*): (.*)\r\n", 0, &err, &res, NULL );
	if ( !re_keyval ) {
		printf( "FATAL: re_keyval error %d: %s\n", res, err );
		return -1;
	}
	
	printf( "=== Session opened ===\n" );
	while ( 1 ) { // mainloop
		if ( buf_offset < MSG_SZ ) {
			len = recv( sock, msg + buf_offset, MSG_SZ, 0 );
			if ( len < 0 ) {
				fprintf( stderr, "FATAL: Error reciving data\n" );
				break;
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
	
	shutdown( sock, SHUT_RDWR );
	return 0;
}
