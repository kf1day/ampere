#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../inc/dba.h"


int dba_init( DB **dbp, const char *path ) {
	int res;

	res = db_create( dbp, NULL, 0 );
	if ( res < 0 ) {
		return -1;
	}

//	(*dbp)->set_flags( *dbp, DB_RECNUM );

	res = (*dbp)->open( *dbp, NULL, path, NULL, DB_BTREE, DB_CREATE, 0 );
	if ( res < 0 ) {
		return -2;
	}

	return 0;
}

void dba_free( DB **dbp ) {
	int res;

	res = (*dbp)->close( *dbp, 0 );
	if ( !res ) {
		free( *dbp );
		*dbp = NULL;
	}
}

int dba_get( DB *dbp, void (*callback)( uint32_t key ) ) {
	int res;
	DBC *pos;
	DBT *key, *val;

	if ( !dbp ) {
		return -2;
	}

	res = dbp->cursor( dbp, NULL, &pos, 0 );
	if ( res < 0 ) {
		return -1;
	}

	key = calloc( 2, sizeof( DBT ) );
	val = key + 1;

	while( pos->get( pos, key, val, DB_NEXT ) == 0 ) {
		callback( *(uint32_t*)key->data );
//		callback( 0x00FAC742 );
	}
	pos->close( pos );
	return 0;
}

int dba_put( DB *dbp, uint32_t addr ) {
	int res;
	DBT *key, *val;

	key = calloc( 2, sizeof( DBT ) );
	val = key + 1;

	key->data = &addr;
	key->size = 4;

	val->data = &addr;
	val->size = 4;

	res = dbp->put( dbp, NULL, key, val, 0 );
	if ( res < 0 ) {
		return -1;
	}
	dbp->sync( dbp, 0 );

	return 0;
}
