#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcre.h>
#include "../inc/vmap.h"
#include "../inc/dba.h"


#define APP_NAME "ampere"
#define APP_VERSION "0.2.1"

#define STR_SZ 256
#define MSG_SZ 1024
#define OVC_SZ 15
#define PATH_SZ 2048

#define DEF_CFG_PATH "/etc/ampere/ampere.cfg"
#define DEF_LIB_PATH "/var/lib/ampere/filter.db"
#define DEF_AMI_USER "ampere"
#define DEF_AMI_PASS "ampere"
#define DEF_FW_CHAIN "ampere"
#define DEF_LOYALTY 3


typedef struct {
	char chain[STR_SZ];
	uint8_t loyalty, mask;
	uint32_t net;
} conf_t;

typedef struct {
	in_addr_t host;
	uint16_t port;
	char user[STR_SZ], pass[STR_SZ], lib[PATH_SZ];
} conf_tmp_t;


int ovc[OVC_SZ];
char *tmp_account, *tmp_address, *tmp_query;
const char *err;
FILE *fd = NULL;

pcre *re_keyval;
pcre *re_ipv4;

conf_t *cfg;
conf_tmp_t *cfg_tmp;

vmap_t *vmap;
DB *dbp;



int key_to_str( uint32_t addr, char *addr_str ) {
	uint8_t o[4];

	memcpy( &o, &addr, 4 );
	sprintf( addr_str, "%hhu.%hhu.%hhu.%hhu", o[3], o[2], o[1], o[0] );
	return 0;
}

int str_to_key( char *addr_str, uint32_t *addr ) {
	uint8_t o[4];
	int res;

	res = sscanf( addr_str, "%hhu.%hhu.%hhu.%hhu", &o[3], &o[2], &o[1], &o[0] );
	if ( res < 0 ) {
		return -1;
	}
	memcpy( addr, &o, 4 );
	return 0;
}

int conf_readln( FILE *fd, char *buf ) {
	char c;
	int i = 0;

	*buf = 0;
	while ( !feof( fd ) ) {
		c = fgetc( fd );
		if ( c < 0 || c == 10 || c == 13 || i + 1 == MSG_SZ ) {
			*(buf+i) = 0;
			return i;
		} else {
			*(buf+i) = c;
			i++;
		}
	}
	*(buf+i) = 0;
	return i;
}

int conf_load( const char *path ) {
	char *ln = malloc( MSG_SZ );
	int res;
	FILE *fd;
	pcre *re_cfg_keyval;

	fd = fopen( path, "r" );
	if ( !fd ) {
		printf( "WARNING: Cannot open config file: \"%s\" - using default values\n", path );
		return -1;
	}
	re_cfg_keyval = pcre_compile( "^\\s*(.*?)\\s*=\\s*(.*)[\\s;#]*.*$", 0, &err, &res, NULL );
	if ( !re_cfg_keyval ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}

	#define _IS( S ) strcmp( ln+ovc[2], S ) == 0
	while ( !feof( fd ) ) {
		res = conf_readln( fd, ln );
		if ( res > 0 ) {
			res = pcre_exec( re_cfg_keyval, NULL, ln, res, 0, 0, ovc, OVC_SZ );
			if ( res == 3 ) {
				*(ln+ovc[3]) = 0;
				*(ln+ovc[5]) = 0;
				if ( _IS( "host" ) ) {
					cfg_tmp->host = inet_addr( ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> host is %s\n", ln+ovc[4] );
					#endif
				} else if ( _IS( "port" ) ) {
					res = atoi( ln+ovc[4] );
					if ( res > 0 ) {
						cfg_tmp->port = res;
						#ifdef DEBUG_FLAG
						printf( " - <conf_load> port is %d\n", cfg_tmp->port );
						#endif
					} else {
						printf( "WARNING: Cannot convert \"port\" value to an integer" );
					}
				} else if ( _IS( "user" ) ) {
					strcpy( cfg_tmp->user, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> user is %s\n", cfg_tmp->user );
					#endif
				} else if ( _IS( "pass" ) ) {
					strcpy( cfg_tmp->pass, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> pass is %s\n", cfg_tmp->pass );
					#endif
				} else if ( _IS( "lib" ) ) {
					strcpy( cfg_tmp->lib, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> lib is %s\n", cfg_tmp->lib );
					#endif
				} else if ( _IS( "net" ) ) {
					res = str_to_key( ln+ovc[4], &cfg->net );
					if ( res < 0 ) {
						cfg->net = 0;
						printf( "WARNING: Cannot convert \"net\" value to an address" );
					#ifdef DEBUG_FLAG
					} else {
						printf( " - <conf_load> net is %s\n", ln+ovc[4] );
					#endif
					}
				} else if ( _IS( "mask" ) ) {
					res = atoi( ln+ovc[4] );
					if ( res > 0 && res <= 32 ) {
						cfg->mask = 32 - res;
						#ifdef DEBUG_FLAG
						printf( " - <conf_load> mask is %d\n", res );
						#endif
					} else {
						printf( "WARNING: Cannot convert \"mask\" value to an integer" );
					}
				} else if ( _IS( "loyalty" ) ) {
					res = atoi( ln+ovc[4] );
					if ( res > 0 ) {
						cfg->loyalty = res;
						#ifdef DEBUG_FLAG
						printf( " - <conf_load> loyalty is %d\n", cfg->loyalty );
						#endif
					} else {
						printf( "WARNING: Cannot convert \"loyalty\" value to an integer" );
					}
				} else if ( _IS( "chain" ) ) {
					strcpy( cfg->chain, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> chain is %s\n", cfg->chain );
					#endif
				}
			}
		}
	}
	fclose( fd );
	return 0;
}

void dbp_get_callback( uint32_t addr ) {
	int res;
	
	key_to_str( addr, tmp_address );
	#ifdef DEBUG_FLAG
	printf( " - <db_read_callback> Blocking %s during startup\n", tmp_address );
	#endif
	sprintf( tmp_query, "iptables -A %s -s %s -j REJECT --reject-with icmp-port-unreachable 2>/dev/null", cfg->chain, tmp_address );
//	printf( "%s\n", tmp_query );
	res = system( tmp_query );
	if ( res != 0 ) {
		printf( "WARNING: failed to insert rule via iptables\n" );
	}
}

int process_msg( char *msg, int len ) {
	int res, re_offset = 0;
	uint8_t state = 0;
	uint32_t addr;

	res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	#define _K( S ) strcmp( msg+ovc[2], S ) == 0
	#define _V( S ) strcmp( msg+ovc[4], S ) == 0
	while ( res == 3 ) {
		*(msg+ovc[3]) = 0;
		*(msg+ovc[5]) = 0;
		re_offset = ovc[1];
		#ifdef DEBUG_FLAG
		printf( "   | %s \"%s\"\n", msg+ovc[2], msg+ovc[4] );
		#endif
		if ( _K( "Response" ) ) {
			if ( _V( "Success" ) ) {
				printf( "Authentication accepted\n" );
				return 0;
			}
			if (_V( "Error" ) ) {
				fprintf( stderr, "ERROR: Authentication failed\n" );
				return -1;
			}
		} else if ( _K( "Event" ) ) {
			if ( _V( "SuccessfulAuth" ) ) state |= 0x80;
			if ( _V( "ChallengeResponseFailed" ) ) state |= 0x40;
			if ( _V( "InvalidPassword" ) ) state |= 0x40;
			if ( _V( "ChallengeSent" ) ) state |= 0x20;
			if ( _V( "FailedACL" ) ) state |= 0x10;
		} else if ( _K( "Service" ) ) {
			if ( _V( "SIP" ) ) state |= 0x08;
			if ( _V( "IAX2" ) ) state |= 0x08;
		} else if ( _K( "RemoteAddress" ) ) {
			strcpy( tmp_address, msg+ovc[4] );
			res = pcre_exec( re_ipv4, NULL, tmp_address, ovc[5] - ovc[4], 0, 0, ovc, OVC_SZ );
			if ( res == 2 ) {
				*(tmp_address+ovc[3]) = 0;
				strcpy( tmp_address, tmp_address + ovc[2] );
				state |= 0x04;
			}
		} else if ( _K( "AccountID" ) ) {
			strcpy( tmp_account, msg+ovc[4] );
			state |= 0x02;
		}
		res = pcre_exec( re_keyval, NULL, msg, len, re_offset, 0, ovc, OVC_SZ );
	}

	#ifdef DEBUG_FLAG
	printf( " - <process_msg> State is 0x%X, account: \"%s\", address: \"%s\"\n", state, tmp_account, tmp_address );
	#endif

	if ( !( state & 0xF0 ) ) {
		#ifdef DEBUG_FLAG
		printf( " - <process_msg> Message does not met required event type\n" );
		#endif
		return 0;
	}
	if ( !( state & 0x08 ) ) {
		#ifdef DEBUG_FLAG
		printf( " - <process_msg> Message does not met required service type\n" );
		#endif
		return 0;
	}

	if ( !( state & 0x04 ) ) {
		printf( "WARNING: Incomplete message - \"RemoteAddress\" is not specified or unknown, skipping\n" );
		return 0;
	}

	if ( !( state & 0x02 ) ) {
		printf( "WARNING: Incomplete message - \"AccountID\" is not specified\n" );
	}

	res = str_to_key( tmp_address, &addr );
	if ( res < 0 ) {
		printf( "WARNING: Cannot translate address: %s\n", tmp_address );
		return 0;
	}

	if ( addr >> cfg->mask == cfg->net >> cfg->mask ) {
		#ifdef DEBUG_FLAG
		printf( " - <process_msg> Skipping internal address\n" );
		#endif
		return 0;
	}

	re_offset = vmap_get( vmap, addr ); // vmap_get generates message itself
	if ( re_offset < 0 ) {
		fprintf( stderr, "FATAL: VMAP exhausted\n" );
		return -2;
	}

	switch ( state ) {
		case 0x8E:
			#ifdef DEBUG_FLAG
			printf( " - <process_msg> Account \"%s\" successfuly logged in from address: \"%s\"\n", tmp_account, tmp_address );
			#endif
			vmap_del( vmap, re_offset );
			return 0;

		case 0x4E:
			vmap->item[re_offset].penalty++;
			break;

		case 0x2E:
			vmap->item[re_offset].penalty += ( vmap->item[re_offset].penalty % 5 == 4 ) ? 10 : 4;
			break;

		case 0x1E:
			vmap->item[re_offset].penalty += ( vmap->item[re_offset].penalty % 5 == 4 ) ? 5 : 4;
			break;

		default:
			printf( "WARNING: unexpected state\n" );
			return 0;
	}

	#ifdef DEBUG_FLAG
	printf( " - <process_msg> Penalty is: %d\n", vmap->item[re_offset].penalty );
	#endif
	if ( 5 * cfg->loyalty <= vmap->item[re_offset].penalty ) {
		printf( "Blocking addres %s\n", tmp_address );
		res = dba_put( dbp, addr );
		if ( res < 0 ) {
			printf( "WARNING: Cannot save address to database\n" );
		}
		sprintf( tmp_query, "iptables -A %s -s %s -j REJECT --reject-with icmp-port-unreachable 2>/dev/null", cfg->chain, tmp_address );
		res = system( tmp_query );
		if ( res != 0 ) {
			printf( "WARNING: Failed to insert rule via iptables\n" );
		}
		vmap_del( vmap, re_offset );
	}

	return 0;
}

int main( int argc, char *argv[] ) {
	int sock, res = 0, len = 1;
	struct sockaddr_in srv;
	uint8_t buf_offset = 0;
	char *msg = malloc( MSG_SZ * 2 ), *buf_start, *buf_end;

	// parsing args
	strcpy( msg, DEF_CFG_PATH );
	#define _ARG( S ) strcmp( argv[len], S ) == 0
	while ( len < argc ) {
		if ( _ARG( "-V" ) ) {
			#ifdef DEBUG_FLAG
			printf( "%s/%s+dev\n", APP_NAME, APP_VERSION );
			#else
			printf( "%s/%s\n", APP_NAME, APP_VERSION );
			#endif
			return 0;
		} else if ( _ARG( "-h" ) || _ARG( "--help" ) ) {
			res = 1;
			break;
		} else if ( _ARG( "-c" ) ) {
			len++;
			if ( len < argc ) {
				strcpy( msg, argv[len] );
				#ifdef DEBUG_FLAG
				printf( " - <main> Config path is set via commandline: \"%s\"\n", msg );
				#endif
			} else {
				res = 2;
				break;
			}
		} else if ( _ARG( "-o" ) || _ARG( "-O" ) ) {
			len++;
			if ( len < argc ) {
				fd = fopen( argv[len], "a" );
				#ifdef DEBUG_FLAG
				printf( " - <main> Config path is set via commandline: \"%s\"\n", msg );
				#endif
			} else {
				res = 2;
				break;
			}
		} else {
			res = 2;
			break;
		}
		len++;
	}
	if( res == 1 ) {
		printf( "Usage: %s [OPTIONS]\n", APP_NAME );
		printf( "Valid options:\n" );
		printf( "  -V                   Display version number and exit\n" );
		printf( "  -c <config>          Use alternative configuration file, default is: %s\n", DEF_CFG_PATH );
		printf( "  -o, -O               Set output to a file" );
		printf( "  -h, --help           Show this help, then exit\n\n" );
		return 0;
	}
	if( res == 2 ) {
		fprintf( stderr, "%s: bad arguments\n", APP_NAME );
		fprintf( stderr, "Try \"%s --help\" for more information\n", argv[0] );
		return -1;
	}

	// init REGEXP parser
	re_keyval = pcre_compile( "(.*?): (.*)\r\n", 0, &err, &res, NULL );
	if ( !re_keyval ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}
	re_ipv4 = pcre_compile( "^IPV4/(?:TCP|UDP)/([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/", 0, &err, &res, NULL );
	if ( !re_ipv4 ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}

	// read config
	cfg = malloc( sizeof( conf_t ) );
	cfg_tmp = malloc( sizeof( conf_tmp_t ) );

	cfg_tmp->host = 0x0100007F; // 127.0.0.1, octet-reversed
	cfg_tmp->port = 5038;
	strcpy( cfg_tmp->user, DEF_AMI_USER );
	strcpy( cfg_tmp->pass, DEF_AMI_PASS );
	strcpy( cfg_tmp->lib, DEF_LIB_PATH );

	cfg->net = 0;
	cfg->mask = 0;
	cfg->loyalty = DEF_LOYALTY;
	strcpy( cfg->chain, DEF_FW_CHAIN );

	res = conf_load( msg ); // conf_load generates message itself
	if ( res < -1 ) {
		return res;
	}


	// init VARS
	tmp_account = malloc( STR_SZ );
	tmp_address = malloc( STR_SZ );
	tmp_query = malloc( STR_SZ );

	vmap_init( vmap );
	res = dba_init( &dbp, cfg_tmp->lib );
	if ( res < 0 ) {
		printf( "ERROR: Failed to open database: \"%s\", code: %d\n", cfg_tmp->lib, res );
		return -1;
	}

	// apply initial fw rules
	sprintf( tmp_query, "iptables -F %s 2>/dev/null", cfg->chain );
	res = system( tmp_query );
	if ( res < 0 ) {
		printf( "WARNING: Cannot flush chain \"%s\"\n", cfg->chain );
	}
	res = dba_get( dbp, dbp_get_callback );
	if ( res < 0 ) {
		fprintf( stderr, "ERROR: Failed to read database\n" );
		return -1;
	}

	// create socket
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock < 0 ) {
		fprintf( stderr, "FATAL: Could not create socket\n" );
		dba_free( &dbp );
		return -2;
	}
	srv.sin_addr.s_addr = cfg_tmp->host;
	srv.sin_family = AF_INET;
	srv.sin_port = htons( cfg_tmp->port );

	// connect to AMI
	res = connect( sock, ( struct sockaddr* ) &srv, sizeof( srv ) );
	if ( res < 0 ) {
		key_to_str( cfg_tmp->host, tmp_address );
		fprintf( stderr, "ERROR: Cannot connect to remote server %s:%d\n", tmp_address, cfg_tmp->port );
		shutdown( sock, SHUT_RDWR );
		dba_free( &dbp );
		return -1;
	}

	// send AUTH message
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\n\r\n", cfg_tmp->user, cfg_tmp->pass );
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		shutdown( sock, SHUT_RDWR );
		dba_free( &dbp );
		return -2;
	}

	free( cfg_tmp );
	cfg_tmp = NULL;

	if ( fd ) {
		fclose( stderr );
		fclose( stdout );
		stdout = fd;
		stderr = fd;
	}
	setbuf( stdout, NULL );

	// mainloop
	printf( "Startup: %s/%s\n", APP_NAME, APP_VERSION );
	while ( 1 ) {
		if ( buf_offset < MSG_SZ ) {
			len = recv( sock, msg + buf_offset, MSG_SZ, 0 );
			if ( len < 0 ) {
				fprintf( stderr, "FATAL: Error reciving data\n" );
				res = -2;
				goto break_mainloop;
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

	printf( "Shutdown\n" );

	shutdown( sock, SHUT_RDWR );
	dba_free( &dbp );
	return res;
}
