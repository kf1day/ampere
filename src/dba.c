#include <stdlib.h>
#include <stdint.h>
#include <db.h>
#include <time.h>
#include "../inc/dba.h"


int dba_init( DB **dbp, const char *path ) {
	int res;

	res = db_create( dbp, NULL, 0 );
	if ( res < 0 ) {
		return -1;
	}

	res = (*dbp)->open( *dbp, NULL, path, NULL, DB_BTREE, DB_CREATE, 0 );
	if ( res < 0 ) {
		return -2;
	}

	return 0;
}

void dba_free( DB *dbp ) {

	dbp->close( dbp, 0 );
}

int dba_get( DB *dbp, void ( *callback )( uint32_t key, time_t val ) ) {
	int res;
	DBC *pos;
	DBT *key, *val;

	res = dbp->cursor( dbp, NULL, &pos, 0 );
	if ( res < 0 ) {
		return -1;
	}

	key = calloc( 2, sizeof( DBT ) );
	val = key + 1;

	while( pos->get( pos, key, val, DB_NEXT ) == 0 ) {
		callback( *(uint32_t*)key->data, *(time_t*)val->data );
	}
	pos->close( pos );
	return 0;
}

int dba_put( DB *dbp, uint32_t addr ) {
	int res;
	DBT *key, *val;
	time_t now;

	key = calloc( 2, sizeof( DBT ) );
	val = key + 1;

	key->data = &addr;
	key->size = 4;

	now = time( NULL );
	val->data = &now;
	val->size = sizeof( time_t );

	res = dbp->put( dbp, NULL, key, val, 0 );
	if ( res < 0 ) {
		return -1;
	}
	dbp->sync( dbp, 0 );

	return 0;
}
