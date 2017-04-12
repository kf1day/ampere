int dba_init( DB **dbp, const char *path );
void dba_free( DB *dbp );
int dba_getall( DB *dbp, void ( *callback )( uint32_t key, time_t val ) );
int dba_put( DB *dbp, uint32_t addr );
int dba_del( DB *dbp, uint32_t addr );
