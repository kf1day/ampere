#include <stdio.h>
#include <sys/stat.h>

#define CONF_STR_SZ 1024
#define CONF_FILE "ampere.cfg"


typedef struct {
	in_addr_t host;
	char user[32], pass[32];
	unsigned short int port;
} conf_t;

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

int conf_load( conf_t *cfg ) {
	const char *err = malloc( CONF_STR_SZ );
	char *ln = malloc( CONF_STR_SZ );
	int res;
	FILE *fd;
	pcre *re_cfg_keyval;
	
	fd = fopen( CONF_FILE, "r" );
	if ( !fd ) {
		fprintf( stderr, "ERROR: Cannot open config file: %s\n", CONF_FILE );
		return -1;
	}
	re_cfg_keyval = pcre_compile( "^([^=#;\\s]*)\\s*=\\s*(.*)$", 0, &err, &res, NULL );
	if ( !re_cfg_keyval ) {
		printf( "FATAL: Cannot compile REGEX: %d - %s\n", res, err );
		return -1;
	}
	
	while ( !feof( fd ) ) {
		res = conf_readln( fd, ln );
		if ( res > 0 ) {
			res = pcre_exec( re_cfg_keyval, NULL, ln, res, 0, 0, ovc, OVC_SZ );
			if ( res == 3 ) {
				*(ln+ovc[3]) = 0;
				*(ln+ovc[5]) = 0;
				if ( strcmp( ln+ovc[2], "host" ) == 0 ) cfg->host = inet_addr( ln+ovc[4] );
				if ( strcmp( ln+ovc[2], "port" ) == 0 ) cfg->port =  atoi( ln+ovc[4] );
				if ( strcmp( ln+ovc[2], "user" ) == 0 ) strcpy( cfg->user, ln+ovc[4] );
				if ( strcmp( ln+ovc[2], "pass" ) == 0 ) strcpy( cfg->pass, ln+ovc[4] );
				
			}
		}
	}
	return 0;
}

//int conf_