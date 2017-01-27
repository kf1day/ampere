#include <stdio.h>			// printf
#include <string.h>			// strlen
#include <stdlib.h>			// malloc
#include <sys/socket.h>		// socket
#include <arpa/inet.h>		// inet_addr
#include <pcre.h>

#define MSG_SZ 1024
#define OVC_SZ 60

#include "conf.h"




typedef struct {
	unsigned char type; // 0 - null, 1 - response, 2 - event
} msg_t;

pcre *re_keyval;
int ovc[OVC_SZ];
char *tmp;


int process_msg( char *msg, int len ) {
	int res, re_offset = 0;
	#define _SUB( A, B ) memcpy( tmp, msg + A, B - A ); *(tmp + B - A) = 0
	unsigned short i;


/*	hit = strstr( msg, "Message: Authentication failed" )
	if ( strstr( msg, "Message: Authentication failed" ) ) {
		fprintf( stderr, "ERROR: Access Denied! Check username and password\n" );
		return -1;
	}*/
	
	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	while ( res && res > 0 ) {
		if ( res > 1 ) {
			for ( i = 1; i < res; i++ ) {
				_SUB( ovc[i*2], ovc[i*2+1] );
				printf( "%s\n", tmp/*, ovc[i*2], ovc[i*2+1]*/ );
			}
		}
		re_offset = ovc[res*2-1];
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}
//	printf( "%s", msg );
	printf( "=== Received %d bytes ===\n", len );
	return 0;
}

int main( int argc, char **argv ){
	int sock, res, len;
	struct sockaddr_in srv;
	unsigned short buf_offset = 0;
	char *msg, *buf_start, *buf_end;
	const char *err;
	
	//string tmp = "Action: Login\r\nUsername: faillog\r\nSecret: 123\r\n\r\nAction: events\r\nEventmask: call\r\n\r\n";
	
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
	tmp = malloc( MSG_SZ );
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\n\r\n", "ampere", "123" );
	
	// send AUTH message
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		return 1;
	}
	printf( "=== Session opened ===\n" );
	
	// init REGEXP parser
	re_keyval = pcre_compile( "^(.*): (.*)$", PCRE_MULTILINE | PCRE_NEWLINE_CRLF, &err, &res, NULL );
	if ( !re_keyval ) {
		printf( "FATAL: re_keyval error %d: %s\n", res, err );
		return -1;
	}
	
	while ( 1 ) {
		
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
						break;
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
				
				if ( res < 0 ) { // error state set by 'process_msg()'
					break;
				}
			}
		} else {
			fprintf( stderr, "WARNING: Buffer too large: %d\n", buf_offset );
			buf_offset = 0;
		}
	}
	
	shutdown( sock, SHUT_RDWR );
	return 0;
}
