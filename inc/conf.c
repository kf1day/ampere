#define CONF_STR_SZ 1024


typedef struct {
	char chain[STR_SZ];
	uint8_t loyalty, mask;
	uint32_t net;
} conf_t;

typedef struct {
	in_addr_t host;
	uint16_t port;
	char user[STR_SZ], pass[STR_SZ], base[PATH_SZ];

} conf_tmp_t;



conf_t *cfg;
conf_tmp_t *cfg_tmp;


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
				} else if ( _IS( "base" ) ) {
					strcpy( cfg_tmp->base, ln+ovc[4] );
					#ifdef DEBUG_FLAG
					printf( " - <conf_load> base is %s\n", cfg_tmp->base );
					#endif
				} else if ( _IS( "net" ) ) {
					res = vmap_atoi( ln+ovc[4], &cfg->net );
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
