#define CONF_STR_SZ 1024


typedef struct {
	in_addr_t host;
	char user[STR_SZ], pass[STR_SZ], chain[STR_SZ];
	uint16_t port;
	uint8_t loyalty;
} conf_t;


conf_t *cfg;


/*******************
 *    INTERFACE    *
 *******************/
int conf_readln( FILE *fd, char *buf );
int conf_load();


/*******************
 *  IPLEMENTATION  *
 *******************/
int conf_readln( FILE *fd, char *buf ) {
	char c;
	int i = 0;

	*buf = 0;
	while ( !feof( fd ) ) {
		c = fgetc( fd );
		if ( c < 0 || c == 10 || c == 13 || i + 1 == CONF_STR_SZ ) {
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
	char *ln = malloc( CONF_STR_SZ );
	int res;
	FILE *fd;
	pcre *re_cfg_keyval;
	
	fd = fopen( path, "r" );
	if ( !fd ) {
		fprintf( stderr, "ERROR: Cannot open config file: %s\n", path );
		return -1;
	}
	re_cfg_keyval = pcre_compile( "^\\s*([^=\\s]*)\\s*=\\s*([^#;\\s]*).*", 0, &err, &res, NULL );
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
					cfg->host = inet_addr( ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - Config: host is %s\n", ln+ovc[4] );
					#endif
				} else if ( _IS( "port" ) ) {
					cfg->port = atoi( ln+ovc[4] ) > 0 ? atoi( ln+ovc[4] ) : 5038;
					#ifdef DEBUG_FLAG
					printf( " - Config: port is %d\n", cfg->port );
					#endif
				} else if ( _IS( "loyalty" ) ) {
					cfg->loyalty = atoi( ln+ovc[4] ) > 0 ? atoi( ln+ovc[4] ) : 3;
					#ifdef DEBUG_FLAG
					printf( " - Config: loyalty is %d\n", cfg->loyalty );
					#endif
				} else if ( _IS( "user" ) ) {
					strcpy( cfg->user, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - Config: user is %s\n", cfg->user );
					#endif
				} else if ( _IS( "pass" ) ) {
					strcpy( cfg->pass, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - Config: pass is %s\n", cfg->pass );
					#endif
				} else if ( _IS( "chain" ) ) {
					strcpy( cfg->chain, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - Config: chain is %s\n", cfg->chain );
					#endif
				}
			}
		}
	}
	return 0;
}
