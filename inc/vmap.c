#define VMAP_SZ 1024


typedef struct {
	in_addr_t addr;
	int16_t fine;
	uint16_t next;
} vmap_t;


uint16_t vmap_index = 0;
vmap_t vmap[VMAP_SZ];


/*******************
 *    INTERFACE    *
 *******************/
int vmap_add( in_addr_t addr, int8_t inc );
int vmap_del( in_addr_t addr );
int vmap_find_addr( in_addr_t addr );


/*******************
 *  IPLEMENTATION  *
 *******************/
int vmap_add( in_addr_t addr, int8_t inc ) {
	int find;
	
	find = vmap_find_addr( addr );
	if ( find < 0 ) {
		vmap[vmap_index].addr = addr;
		vmap[vmap_index].fine = inc;
		#ifdef debug
		printf( "Set fine %d to 0x%X at pos %d\n", inc, addr, vmap_index ); // inet_ntoa( *(struct in_addr*)&addr )
		#endif
		if ( vmap[vmap_index].next > 0 ) {
			vmap_index = vmap[vmap_index].next;
		} else if ( vmap_index < VMAP_SZ - 2 ) {
			vmap_index++;
		} else {
			fprintf( stderr, "FATAL: Array of VMap exhausted\n" );
			return -2;
		}
	} else {
		vmap[find].fine += inc;
		#ifdef debug
		printf( "Set fine %d to 0x%X at pos %d\n", vmap[find].fine, addr, find );
		#endif
		if ( vmap[find].fine < 0 ) {
			return 0;
		} else {
			return vmap[find].fine;
		}
	}
	if ( inc < 0 ) {
		return 0;
	} else {
		return inc;
	}
}

int vmap_del( in_addr_t addr ) {
	int find;

	find = vmap_find_addr( addr );
	if ( find < 0 ) {
		return -1;
	} else {
		vmap[find].addr = 0;
		vmap[find].fine = 0;
		vmap[find].next = vmap_index;
		vmap_index = find;
		#ifdef debug
		printf( "Drop fines from 0x%X at pos %d\n", addr, find );
		#endif
	}
	return 0;
}

int vmap_find_addr( in_addr_t addr ) {
	uint16_t i;
		
	for ( i = 0; i < VMAP_SZ; i++ ) {
		if ( vmap[i].addr == addr ) {
			return i;
		}
	}
	return -1;
	
}

