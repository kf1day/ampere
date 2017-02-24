#define VMAP_SZ 1024


typedef struct {
	uint32_t addr;
	uint8_t penalty;
	uint16_t next;
} vmap_t;


uint16_t vmap_index = 0;
vmap_t vmap[VMAP_SZ];


/*******************
 *    INTERFACE    *
 *******************/
int vmap_del( vmap_t *vmap_offset );
vmap_t* vmap_get( uint32_t addr );
int vmap_itos( uint32_t addr, char *addr_str );
int vmap_atoi( char *addr_str, uint32_t *addr );


/*******************
 *  IPLEMENTATION  *
 *******************/
int vmap_del( vmap_t *vmap_offset ) {
	int index;

	index = vmap_offset - vmap;
	if ( 0 <= index && index < VMAP_SZ ) {
		vmap[index].addr = 0;
		vmap[index].next = vmap_index;
		vmap_index = index;
		#ifdef DEBUG_FLAG
		printf( " - <vmap_del> Del existing HOST at index %d\n", index );
		#endif
		return 0;
	} else {
		return -1;
	}
}

vmap_t* vmap_get( uint32_t addr ) {
	uint16_t i;

	for ( i = 0; i < VMAP_SZ; i++ ) {
		if ( vmap[i].addr == addr ) {
			#ifdef DEBUG_FLAG
			printf( " - <vmap_get> Got existing HOST at index %d\n", i );
			#endif
			return &vmap[i];
		}
	}
	i = vmap_index;
	if ( i < VMAP_SZ ) {
		if ( vmap[i].next == 0 ) {
			vmap_index++;
		} else {
			vmap_index = vmap[i].next;
		}
		#ifdef DEBUG_FLAG
		printf( " - <vmap_get> Add new HOST at index %d\n", i );
		#endif
		vmap[i].addr = addr;
		vmap[i].penalty = 0;
		vmap[i].next = 0;
		return &vmap[i];
	} else {
		return NULL;
	}

}

int vmap_itos( uint32_t addr, char *addr_str ) {
	uint8_t o[4];

	memcpy( &o, &addr, 4 );
	sprintf( addr_str, "%hhu.%hhu.%hhu.%hhu", o[3], o[2], o[1], o[0] );
	return 0;
}

int vmap_atoi( char *addr_str, uint32_t *addr ) {
	uint8_t o[4];
	int res;

	res = sscanf( addr_str, "%hhu.%hhu.%hhu.%hhu", &o[3], &o[2], &o[1], &o[0] );
	if ( res < 0 ) {
		return -1;
	}
	memcpy( addr, &o, 4 );
	return 0;
}
