#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcre.h>


#define STR_SZ 256
#define MSG_SZ 4*STR_SZ
#define OVC_SZ 15


pcre *re_keyval;
pcre *re_ipv4;
int ovc[OVC_SZ];
char *tmp_account, *tmp_address;
const char *err;


#include "conf.h"
#include "vmap.h"


int process_msg( char *msg, int len ) {
	#define _K( S ) strcmp( msg+ovc[2], S ) == 0
	#define _V( S ) strcmp( msg+ovc[4], S ) == 0
	int res, re_offset = 0;
	uint8_t state = 0;

	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	printf( "\n>>>>>>>>>>>>>>>>>>>>\n" );		// debug
	while ( res == 3 ) {
		*(msg+ovc[3]) = 0;
		*(msg+ovc[5]) = 0;
		re_offset = ovc[1];
		printf( "%s -> %s\n", msg+ovc[2], msg+ovc[4] );		// debug
		if ( _K( "Response"	) && _V( "Success" ) ) {
			state += 0x10;
		} else if ( _K( "Response"	) && _V( "Error" ) ) {
			state += 0x20;
		} else if ( _K( "Event"	) && _V( "ChallengeSent" ) ) {
			state += 0x30;
		} else if ( _K( "ActionID"	) && _V( "AmpereX7E1" ) ) {
			state += 0x01;
		} else if ( _K( "AccountID"	) ) {
			memcpy( tmp_account, msg+ovc[4], ovc[5] - ovc[4] + 1 );
		} else if ( _K( "RemoteAddress"	) ) {
			memcpy( tmp_address, msg+ovc[4], ovc[5] - ovc[4] + 1 );
			res = pcre_exec( re_ipv4, NULL, tmp_address, ovc[5] - ovc[4], 0, 0, ovc, OVC_SZ );
			if ( res == 3 ) {
				memcpy( tmp_address, tmp_address + ovc[4], ovc[5] - ovc[4] );
				*(tmp_address+ovc[5]-ovc[4]) = 0;
				state += 0x01;
			} else {
				state += 0x02;
			}
		}
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}
	printf( "<<<<<<<<<<<<<<<<<<<<\n\n" );		// debug

	switch ( state ) {
		case 0x11:
			printf( "Authentication accepted\n" );
			break;
		case 0x21:
			fprintf( stderr, "ERROR: Authentication failed\n" );
			return -1;
		case 0x31:
			printf( "Open challenge warning for account %s from %x\n", tmp_account, inet_addr( tmp_address ) );
			break;
		case 0x32:
			printf( "Cannot parse IP for account %s: %s\n", tmp_account, tmp_address );
			break;
	}
//	vmap_add( 0x0100007f, 1 );
//	printf( "Received %d bytes\n", len );
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
	cfg->host = 0x0100007F; // 127.0.0.1
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
	
	// init VARS
	tmp_account = malloc( STR_SZ );
	tmp_address = malloc( STR_SZ );
	msg = malloc( MSG_SZ * 2 );
	memset( &vmap, 0, sizeof( vmap ) );
	
	// send AUTH message
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\nActionID: AmpereX7E1\r\n\r\n", cfg->user, cfg->pass );
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
	re_ipv4 = pcre_compile( "^IPV4/(TCP|UDP)/([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/", 0, &err, &res, NULL );
	if ( !re_ipv4 ) {
		printf( "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		shutdown( sock, SHUT_RDWR );
		return -2;
	}
	
	printf( "Session opened\n" );
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
	
	printf( "Session closed\n" );

	shutdown( sock, SHUT_RDWR );
	return 0;
}
