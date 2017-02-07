#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcre.h>
#include <sqlite3.h>
//#include <libiptc/libiptc.h>


#define STR_SZ 256
#define MSG_SZ 4*STR_SZ
#define OVC_SZ 15

// This will be cofigurable
#define DB_PATH "filter.sqlite"


pcre *re_keyval;
pcre *re_ipv4;
int ovc[OVC_SZ];
char *tmp_account, *tmp_address, *tmp_query;
const char *err;

sqlite3 *db;


#include "inc/conf.c"
#include "inc/vmap.c"

static int db_write_callback( void *z, int argc, char **argv, char **col_name ) {
/*	int i;
	
	for( i = 0; i < argc; i++ ) {
		printf( "%s = %s\n", col_name[i], argv[i] ? argv[i] : "NULL" );
	}
	printf( "\n" );*/
	return 0;
}

static int db_read_callback( void *z, int argc, char **argv, char **col_name ) {
	int i, res;
	in_addr_t ip;
	
	for( i = 0; i < argc; i++ ) {
		ip = atol( argv[i] );
		if ( ip > 0 ) {
			vmap_addr_to_string( ip, tmp_address );
			#ifdef DEBUG_FLAG
			printf( "### Blocking %s during initialize\n", tmp_address );
			#endif
			sprintf( tmp_query, "iptables -I %s 1 -s %s -j REJECT --reject-with icmp-port-unreachable", cfg->chain, tmp_address );
			res = system( tmp_query );
			if ( res != 0 ) {
				printf( "WARNING: failed to insert rule via iptables\n" );
			}			
		} else {
			printf( "WARNING: Cannot convert IP from database record: %s\n", argv[i] ? argv[i] : "NULL" );
		}
	}
	return 0;
}


int process_msg( char *msg, int len ) {
	#define _K( S ) strcmp( msg+ovc[2], S ) == 0
	#define _V( S ) strcmp( msg+ovc[4], S ) == 0
	int res, re_offset = 0;
	uint8_t state = 0;

	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	#ifdef DEBUG_FLAG
	printf( "### >>>>>>>>>>\n" );
	#endif
	while ( res == 3 ) {
		*(msg+ovc[3]) = 0;
		*(msg+ovc[5]) = 0;
		re_offset = ovc[1];
		#ifdef DEBUG_FLAG
		printf( "### %s -> %s\n", msg+ovc[2], msg+ovc[4] );
		#endif
		if ( _K( "Response" ) ) {
			if ( _V( "Success" ) ) state = 0x01;
			if (_V( "Error" ) ) state = 0x02;
		} else if ( _K( "Event" ) ) {
			if ( _V( "SuccessfulAuth" ) ) state = 0x03;
			if ( _V( "ChallengeSent" ) ) state = 0x04;
			if ( _V( "ChallengeResponseFailed" ) ) state = 0x05;
			if ( _V( "InvalidPassword" ) ) state = 0x06;
		}
		if ( _K( "ActionID" ) && _V( "AmpereX7E1" ) )	state += 0x10;
		if ( _K( "AccountID" ) ) memcpy( tmp_account, msg+ovc[4], ovc[5] - ovc[4] + 1 );
		if ( _K( "RemoteAddress" ) ) {
			memcpy( tmp_address, msg+ovc[4], ovc[5] - ovc[4] + 1 );
			res = pcre_exec( re_ipv4, NULL, tmp_address, ovc[5] - ovc[4], 0, 0, ovc, OVC_SZ );
			if ( res == 3 ) {
				memcpy( tmp_address, tmp_address + ovc[4], ovc[5] - ovc[4] );
				*(tmp_address+ovc[5]-ovc[4]) = 0;
				state += 0x20;
			} else {
				state += 0x40;
			}
		}
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}
	#ifdef DEBUG_FLAG
	printf( "### <<<<<<<<<<\n" );
	#endif
	
	res = 0;

	switch ( state ) {
		case 0x11:
			printf( "Authentication accepted\n" );
			break;
		case 0x12:
			fprintf( stderr, "ERROR: Authentication failed\n" );
			return -1;
		case 0x23:
			res = vmap_del( inet_addr( tmp_address ) );
			break;
		case 0x24:
			res = vmap_add( inet_addr( tmp_address ), 4 );
			if ( res < 0 ) {
				return res;
			} else {
				break;
			}
		case 0x25:
		case 0x26:
			res = vmap_add( inet_addr( tmp_address ), 1 );
			if ( res < 0 ) {
				return res;
			} else {
				break;
			}
		case 0x43:
		case 0x44:
			printf( "WARNING: Cannot parse IP for account %s: %s\n", tmp_account, tmp_address );
			break;
	}
	if ( res >= 5 * cfg->loyalty ) {
		printf( "Blocking addres %s\n", tmp_address );
		sprintf( tmp_query, "INSERT OR REPLACE INTO filter(addr, id) VALUES (%ld, \"%s\");", (long int)inet_addr( tmp_address ), tmp_account );
		res = sqlite3_exec( db, tmp_query, db_write_callback, 0, (char **)&err );
		if ( res != SQLITE_OK ) {
			fprintf( stderr, "ERROR (SQL): %s\n", err );
			return -1;
		}
		sprintf( tmp_query, "iptables -I %s 1 -s %s -j REJECT --reject-with icmp-port-unreachable", cfg->chain, tmp_address );
		res = system( tmp_query );
		if ( res != 0 ) {
			printf( "WARNING: failed to insert rule via iptables\n" );
		}
		vmap_del( inet_addr( tmp_address ) );
	}
	return 0;
}

int main( int argc, char **argv ) {
	int sock, res, len;
	struct sockaddr_in srv;
	uint8_t buf_offset = 0;
	char *msg, *buf_start, *buf_end;
	
	// init REGEXP parser
	re_keyval = pcre_compile( "(.*): (.*)\r\n", 0, &err, &res, NULL );
	if ( !re_keyval ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}
	re_ipv4 = pcre_compile( "^IPV4/(TCP|UDP)/([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/", 0, &err, &res, NULL );
	if ( !re_ipv4 ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}
	
	// read config
	cfg = malloc( sizeof( conf_t ) );
	cfg->host = 0x0100007F; // 127.0.0.1, octet-reversed
	cfg->port = 5038;
	cfg->loyalty = 3;
	strcpy( cfg->user, "ampere" );
	strcpy( cfg->pass, "ampere" );
	strcpy( cfg->chain, "ampere" );
	res = conf_load();
	if ( res < 0 ) {
		return res;
	}
	
	// init VARS
	tmp_account = malloc( STR_SZ );
	tmp_address = malloc( STR_SZ );
	tmp_query = malloc( STR_SZ );
	msg = malloc( MSG_SZ * 2 );
	memset( &vmap, 0, sizeof( vmap ) );
	
	// init SQLITE
	res = sqlite3_open( DB_PATH, &db );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Could not open database\n" );
		return -2;
	}
	res = sqlite3_exec( db, "CREATE TABLE IF NOT EXISTS filter( addr INT PRIMARY KEY NOT NULL, id TEXT );", db_write_callback, 0, (char **)&err );
	if ( res != SQLITE_OK ) {
		fprintf( stderr, "ERROR (SQL): %s\n", err );
		sqlite3_close( db );
		return -1;
	}
	
	// apply initial fw rules
	sprintf( tmp_query, "iptables -F %s", cfg->chain );
	system( tmp_query );
	sprintf( tmp_query, "iptables -A %s -j RETURN", cfg->chain );
	system( tmp_query );
	res = sqlite3_exec( db, "SELECT addr FROM filter;", db_read_callback, 0, (char **)&err );
	if ( res != SQLITE_OK ) {
		fprintf( stderr, "ERROR (SQL): %s\n", err );
		sqlite3_close( db );
		return -1;
	}
	
	// create socket
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock < 0 ) {
		fprintf( stderr, "FATAL: Could not create socket\n" );
		sqlite3_close( db );
		return -2;
	}
	srv.sin_addr.s_addr = cfg->host;
	srv.sin_family = AF_INET;
	srv.sin_port = htons( cfg->port );
	
	// connect to AMI
	res = connect( sock, ( struct sockaddr* ) &srv, sizeof( srv ) );
	if ( res < 0 ) {
		vmap_addr_to_string( cfg->host, tmp_address );
		fprintf( stderr, "ERROR: Cannot connect to remote server %s:%d\n", tmp_address, cfg->port );
		shutdown( sock, SHUT_RDWR );
		sqlite3_close( db );
		return -1;
	}
	
	// send AUTH message
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\nActionID: AmpereX7E1\r\n\r\n", cfg->user, cfg->pass );
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		shutdown( sock, SHUT_RDWR );
		sqlite3_close( db );
		return -2;
	}

	// mainloop
	printf( "Session opened\n" );
	while ( 1 ) {
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
			printf( "WARNING: Buffer too large: %d\n", buf_offset );
			buf_offset = 0;
		}
	}
	break_mainloop:;
	
	printf( "Session closed\n" );

	shutdown( sock, SHUT_RDWR );
	sqlite3_close( db );
	return 0;
}
