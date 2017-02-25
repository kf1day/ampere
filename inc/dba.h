#include <db.h>


int dba_init( DB **dbp, const char *path );
void dba_free( DB **dbp );
int dba_get( DB *dbp, void (*callback)( uint32_t key ) );
int dba_put( DB *dbp, uint32_t addr );
