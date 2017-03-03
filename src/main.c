#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <db.h>
#include <pcre.h>
#include "../inc/vmap.h"
#include "../inc/dba.h"


#define APP_NAME "ampere"
#define APP_VERSION "0.2.2"

#define STR_SZ 256
#define MSG_SZ 1024
#define OVC_SZ 15
#define PATH_SZ 2048

// this will be configurable at build-time
#define CFG_PATH "/etc/ampere/ampere.cfg"
#define LIB_PATH "/var/lib/ampere/filter.db"

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



int key_intstr( uint32_t addr, char *addr_str ) {
	uint8_t o[4];

	memcpy( &o, &addr, 4 );
	sprintf( addr_str, "%hhu.%hhu.%hhu.%hhu", o[3], o[2], o[1], o[0] );
	return 0;
}

int key_strint( const char *addr_str, uint32_t *addr ) {
	uint8_t o[4];
	int res;

	res = sscanf( addr_str, "%hhu.%hhu.%hhu.%hhu", &o[3], &o[2], &o[1], &o[0] );
	if ( res != 4 ) {
		return -1;
	}
	memcpy( addr, &o, 4 );
	return 0;
}

int fd_readln( FILE *fd, char *buf ) {
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
	char *ln = malloc( MSG_SZ ), *ch;
	int res;
	FILE *fd;
	pcre *re_cfg_keyval;

	fd = fopen( path, "r" );
	if ( !fd ) {
		fprintf( stdout,  "WARNING: Cannot open config file: \"%s\" - using default values\n", path );
		fflush( stdout );
		return 1;
	}
	re_cfg_keyval = pcre_compile( "^\\s*(.*?)\\s*=\\s*(.*)[\\s;#]*.*$", 0, &err, &res, NULL );
	if ( !re_cfg_keyval ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -2;
	}

	#define _IS( S ) strcmp( ln+ovc[2], S ) == 0
	while ( !feof( fd ) ) {
		res = fd_readln( fd, ln );
		if ( res > 0 ) {
			res = pcre_exec( re_cfg_keyval, NULL, ln, res, 0, 0, ovc, OVC_SZ );
			if ( res == 3 ) {
				*(ln+ovc[3]) = 0;
				*(ln+ovc[5]) = 0;
				if ( _IS( "host" ) ) {
					cfg_tmp->host = inet_addr( ln+ovc[4] );

				} else if ( _IS( "port" ) ) {
					res = atoi( ln+ovc[4] );
					if ( res > 0 ) {
						cfg_tmp->port = res;
					} else {
						fprintf( stdout, "WARNING: Skipping incorrect \"port\" value\n" );
						fflush( stdout );
					}

				} else if ( _IS( "user" ) ) {
					strcpy( cfg_tmp->user, ln+ovc[4] );

				} else if ( _IS( "pass" ) ) {
					strcpy( cfg_tmp->pass, ln+ovc[4] );

				} else if ( _IS( "trust" ) ) {
					ch = strstr( ln+ovc[4], "/" );
					if ( ch ) {
						*ch = 0;
						res = atoi( ch+1 );
						if ( res > 0 && res <= 32 ) {
							cfg->mask = 32 - res;
						} else {
							fprintf( stdout, "WARNING: Skipping incorrect \"trust\" (mask) value\n" );
							fflush( stdout );
						}
					}
					res = key_strint( ln+ovc[4], &cfg->net );
					if ( res < 0 ) {
						cfg->mask = 0;
						fprintf( stdout, "WARNING: Skipping incorrect \"trust\" value\n" );
						fflush( stdout );
					}

				} else if ( _IS( "loyalty" ) ) {
					res = atoi( ln+ovc[4] );
					if ( res > 0 ) {
						cfg->loyalty = res;
					} else {
						fprintf( stdout, "WARNING: Skipping incorrect \"loyalty\" value\n" );
						fflush( stdout );
					}

				} else if ( _IS( "chain" ) ) {
					strcpy( cfg->chain, ln+ovc[4] );
				}
			}
		}
	}
	fclose( fd );
	return 0;
}

void callback_filter( uint32_t addr, time_t time ) {
	int res;

	key_intstr( addr, tmp_address );
	sprintf( tmp_query, "iptables -A %s -s %s -j REJECT --reject-with icmp-port-unreachable 2>/dev/null", cfg->chain, tmp_address );
	res = system( tmp_query );
	if ( res != 0 ) {
		fprintf( stdout, "WARNING: failed to insert rule via iptables\n" );
		fflush( stdout );
	}
}

void callback_dump( uint32_t addr, time_t time ) {
	struct tm *timestamp;

	timestamp = localtime( &time );

	key_intstr( addr, tmp_address );
	strftime( tmp_query, STR_SZ, "%Y-%m-%d %H:%M:%S", timestamp );
	fprintf( stdout, " %15s | since %s\n", tmp_address, tmp_query );
	fflush( stdout );
}

void db_put( char *addr_str ) {
	uint32_t addr;
	int res;

	res = key_strint( addr_str, &addr );
	if ( res < 0 ) {
		fprintf( stdout, "WARNING: Cannot translate address: \"%s\"\n", addr_str );
		fflush( stdout );
	} else {
		dba_put( dbp, addr );
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
		fprintf( stdout, "   | %20s | %s\n", msg+ovc[2], msg+ovc[4] );
		#endif
		if ( _K( "Response" ) && _V( "Error" ) ) {
			fprintf( stderr, "ERROR: Authentication failed\n" );
			return -1;

		} else if ( _K( "Event" ) ) {
			if ( _V( "SuccessfulAuth" ) ) state |= 0x80;
			if ( _V( "ChallengeResponseFailed" ) ) state |= 0x40;
			if ( _V( "InvalidPassword" ) ) state |= 0x40;
			if ( _V( "ChallengeSent" ) ) state |= 0x20;
			if ( _V( "FailedACL" ) ) state |= 0x10;
			if ( _V( "Shutdown" ) ) {
				fprintf( stdout, "Got shutdown message, terminating\n" );
				fflush( stdout );
				return -1;
			}

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
	fprintf( stdout, "   |----------------------| State is 0x%X, account: \"%s\", address: \"%s\"\n", state, tmp_account, tmp_address );
	fflush( stdout );
	#endif

	if ( !( state & 0xF0 ) ) {
		#ifdef DEBUG_FLAG
		fprintf( stdout, "   |----------------------| Message does not met required event type\n" );
		fflush( stdout );
		#endif
		return 0;
	}
	if ( !( state & 0x08 ) ) {
		#ifdef DEBUG_FLAG
		fprintf( stdout, "   |----------------------| Message does not met required service type\n" );
		fflush( stdout );
		#endif
		return 0;
	}

	if ( !( state & 0x04 ) ) {
		fprintf( stdout, "WARNING: Incomplete message - \"RemoteAddress\" is not specified or unknown, skipping\n" );
		fflush( stdout );
		return 0;
	}

	if ( !( state & 0x02 ) ) {
		fprintf( stdout, "WARNING: Incomplete message - \"AccountID\" is not specified\n" );
		fflush( stdout );
	}

	res = key_strint( tmp_address, &addr );
	if ( res < 0 ) {
		fprintf( stdout, "WARNING: Cannot translate address: %s\n", tmp_address );
		fflush( stdout );
		return 0;
	}

	if ( addr >> cfg->mask == cfg->net >> cfg->mask ) {
		#ifdef DEBUG_FLAG
		fprintf( stdout, "   |----------------------| Skipping internal address\n" );
		fflush( stdout );
		#endif
		return 0;
	}

	re_offset = vmap_get( vmap, addr );
	if ( re_offset < 0 ) {
		fprintf( stderr, "FATAL: VMAP exhausted\n" );
		return -2;
	}

	switch ( state ) {
		case 0x8E:
			#ifdef DEBUG_FLAG
			fprintf( stdout, "   |----------------------| Account \"%s\" successfuly logged in from address: \"%s\"\n", tmp_account, tmp_address );
			fflush( stdout );
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
			fprintf( stdout, "WARNING: unexpected state\n" );
			fflush( stdout );
			return 0;
	}

	#ifdef DEBUG_FLAG
	fprintf( stdout, "   |----------------------| Penalty is: %d\n", vmap->item[re_offset].penalty );
	fflush( stdout );
	#endif
	if ( 5 * cfg->loyalty <= vmap->item[re_offset].penalty ) {
		fprintf( stdout, "Blocking addres %s\n", tmp_address );
		fflush( stdout );
		res = dba_put( dbp, addr );
		if ( res < 0 ) {
			fprintf( stdout, "WARNING: Cannot save address to database\n" );
			fflush( stdout );
		}
		sprintf( tmp_query, "iptables -A %s -s %s -j REJECT --reject-with icmp-port-unreachable 2>/dev/null", cfg->chain, tmp_address );
		res = system( tmp_query );
		if ( res != 0 ) {
			fprintf( stdout, "WARNING: Failed to insert rule via iptables\n" );
			fflush( stdout );
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
	strcpy( msg, CFG_PATH );
	#define _ARG( S ) strcmp( argv[len], S ) == 0
	while ( len < argc ) {
		if ( _ARG( "-h" ) || _ARG( "--help" ) ) {
			fprintf( stdout, "Usage: %s [OPTIONS]\n", APP_NAME );
			fprintf( stdout, "Valid options:\n" );
			fprintf( stdout, "  -h, --help           Show this help, then exit\n" );
			fprintf( stdout, "  -V, --version        Display version number and exit\n" );
			fprintf( stdout, "  -a, --add            Populate database with addresses from a pipeline\n" );
			fprintf( stdout, "  -l, --list           List database entries and exit\n" );
			fprintf( stdout, "  -c <config>          Use alternative configuration file, default is: %s\n", CFG_PATH );
			fprintf( stdout, "  -o <logfile>         Set output stream to a file\n\n" );
			fflush( stdout );
			return 0;

		} else if ( _ARG( "-V" ) || _ARG( "--version" ) ) {
			#ifdef DEBUG_FLAG
			fprintf( stdout, "%s/%s+dev\n", APP_NAME, APP_VERSION );
			#else
			fprintf( stdout, "%s/%s\n", APP_NAME, APP_VERSION );
			#endif
			fflush( stdout );
			return 0;

		} else if ( _ARG( "-a" ) || _ARG( "--add" ) ) {
			if ( isatty( STDIN_FILENO ) ) {
				fprintf( stderr, "ERROR: Not in a pipline\n" );
				return -1;
			} else {
				buf_offset = 1;
				break;
			}

		} else if ( _ARG( "-l" ) || _ARG( "--list" ) ) {
			buf_offset = 2;
			break;

		} else if ( _ARG( "-c" ) ) {
			len++;
			if ( len < argc ) {
				strcpy( msg, argv[len] );
				#ifdef DEBUG_FLAG
				fprintf( stdout, "   <main> Config path is set via commandline: \"%s\"\n", msg );
				fflush( stdout );
				#endif
			} else {
				res = -1;
				break;
			}

		} else if ( _ARG( "-o" ) ) {
			len++;
			if ( len < argc ) {
				fd = fopen( argv[len], "a" );
				#ifdef DEBUG_FLAG
				fprintf( stdout, "   <main> Output path is set via commandline: \"%s\"\n", msg );
				fflush( stdout );
				#endif
			} else {
				res = -1;
				break;
			}
		} else {
			res = -1;
			break;
		}
		len++;
	}
	if( res < 0 ) {
		fprintf( stderr, "%s: bad arguments\n", APP_NAME );
		fprintf( stderr, "Try \"%s --help\" for more information\n", argv[0] );
		return -1;
	}


	// init VARS
	tmp_account = malloc( STR_SZ );
	tmp_address = malloc( STR_SZ );
	tmp_query = malloc( STR_SZ );
	vmap_init( &vmap );
	res = dba_init( &dbp, LIB_PATH );
	if ( res < 0 ) {
		fprintf( stderr, "ERROR: Failed to open database: \"%s\"\n", LIB_PATH );
		return -1;
	}

	if ( buf_offset == 1 ) {
		while( !feof( stdin ) ) {
			res = fd_readln( stdin, msg );
			if ( res > 0 ) {
				#ifdef DEBUG_FLAG
				fprintf( stdout, "   <main> Processing value: \"%s\"\n", msg );
				fflush( stdout );
				#endif
				db_put( msg );
			}
		}
		res = 0;
		goto shutdown_dba;
	}

	if ( buf_offset == 2 ) {
		res = dba_get( dbp, callback_dump );
		if ( res < 0 ) {
			fprintf( stderr, "ERROR: Failed to read database\n" );
			res = -1;
		}
		goto shutdown_dba;
	}


	// init REGEXP parser
	re_keyval = pcre_compile( "(.*?): (.*)\r\n", 0, &err, &res, NULL );
	if ( !re_keyval ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		res = -2;
		goto shutdown_dba;
	}
	re_ipv4 = pcre_compile( "^IPV4/(?:TCP|UDP)/([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/", 0, &err, &res, NULL );
	if ( !re_ipv4 ) {
		fprintf( stderr, "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		res = -2;
		goto shutdown_dba;
	}


	// read config
	cfg = malloc( sizeof( conf_t ) );
	cfg_tmp = malloc( sizeof( conf_tmp_t ) );

	cfg_tmp->host = 0x0100007F; // 127.0.0.1, octet-reversed
	cfg_tmp->port = 5038;
	strcpy( cfg_tmp->user, DEF_AMI_USER );
	strcpy( cfg_tmp->pass, DEF_AMI_PASS );

	cfg->net = 0;
	cfg->mask = 0;
	cfg->loyalty = DEF_LOYALTY;
	strcpy( cfg->chain, DEF_FW_CHAIN );

	res = conf_load( msg ); // conf_load generates message itself
	if ( res < 0 ) {
		goto shutdown_dba;
	}


	// apply initial fw rules
	sprintf( tmp_query, "iptables -F %s 2>/dev/null", cfg->chain );
	res = system( tmp_query );
	if ( res < 0 ) {
		fprintf( stdout, "WARNING: Cannot flush chain \"%s\"\n", cfg->chain );
		fflush( stdout );
	}
	res = dba_get( dbp, callback_filter );
	if ( res < 0 ) {
		fprintf( stderr, "ERROR: Failed to read database\n" );
		res = -1;
		goto shutdown_dba;
	}


	// create socket
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock < 0 ) {
		fprintf( stderr, "FATAL: Could not create socket\n" );
		res = -2;
		goto shutdown_dba;
	}
	srv.sin_addr.s_addr = cfg_tmp->host;
	srv.sin_family = AF_INET;
	srv.sin_port = htons( cfg_tmp->port );


	// connect to AMI
	res = connect( sock, ( struct sockaddr* ) &srv, sizeof( srv ) );
	if ( res < 0 ) {
		key_intstr( cfg_tmp->host, tmp_address );
		fprintf( stderr, "ERROR: Cannot connect to remote server %s:%d\n", tmp_address, cfg_tmp->port );
		res = -1;
		goto shutdown_sock;
	}


	// send AUTH message
	sprintf( msg, "Action: Login\r\nUsername: %s\r\nSecret: %s\r\n\r\n", cfg_tmp->user, cfg_tmp->pass );
	res = send( sock, msg, strlen( msg ), 0 );
	if ( res < 0 ) {
		fprintf( stderr, "FATAL: Send failed\n" );
		res = -2;
		goto shutdown_sock;
	}

	free( cfg_tmp );
	cfg_tmp = NULL;
	fclose( stdin );
	fflush( stdout );
	if ( fd ) {
		fclose( stderr );
		fclose( stdout );
		stdout = fd;
		stderr = fd;
	}
	chdir( "/" );


	// mainloop
	fprintf( stdout, "Startup: %s/%s\n", APP_NAME, APP_VERSION );
	fflush( stdout );
	while ( 1 ) {
		if ( buf_offset < MSG_SZ ) {
			len = recv( sock, msg + buf_offset, MSG_SZ, 0 );
			if ( len < 0 ) {
				fprintf( stderr, "FATAL: Error reciving data\n" );
				res = -2;
				goto shutdown_sock;
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
						goto shutdown_sock;
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
			fprintf( stdout, "WARNING: Buffer too large: %d\n", buf_offset );
			fflush( stdout );
			buf_offset = 0;
		}
	}
	shutdown_sock:;
	shutdown( sock, SHUT_RDWR );

	shutdown_dba:;
	dba_free( dbp );
	return res;
}
