#define VMAP_SZ 1024


typedef struct {
	in_addr_t addr;
	int16_t penalty;
	uint16_t next;
} vmap_t;


uint16_t vmap_index = 0;
vmap_t vmap[VMAP_SZ];


/*******************
 *    INTERFACE    *
 *******************/
int vmap_del( vmap_t *vmap_offset );
vmap_t* vmap_get( in_addr_t addr );
void vmap_itos( in_addr_t addr, char *addr_str );

/*******************
 *  IPLEMENTATION  *
 *******************/
int vmap_del( vmap_t *vmap_offset ) {
	int index;
	
	index = ( vmap_offset - vmap ) / sizeof( vmap_t );
	if ( 0 <= index && index < VMAP_SZ ) {
		vmap[index].addr = 0;
		vmap[index].next = vmap_index;
		vmap_index = index;
		#ifdef DEBUG_FLAG
		printf( " - Remove existing VX at index %d\n", index );
		#endif
		return 0;
	} else {
		#ifdef DEBUG_FLAG
		printf( " - Index out of bounds: %d\n", index );
		#endif
		return -1;
	}
}

vmap_t* vmap_get( in_addr_t addr ) {
	uint16_t i;
		
	for ( i = 0; i < VMAP_SZ; i++ ) {
		if ( vmap[i].addr == addr ) {
			#ifdef DEBUG_FLAG
			printf( " - Got existing VX at index %d\n", i );
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
		printf( " - Initialled new VX at index %d\n", i );
		#endif
		vmap[i].addr = addr;
		vmap[i].penalty = 0;
		vmap[i].next = 0;
		return &vmap[i];
	} else {
		return NULL;
	}
	
}

void vmap_itos( in_addr_t addr, char *addr_str ) {
	uint8_t o[4];
	
	o[0] = addr / 0x1000000;
	o[1] = addr / 0x10000 % 0x100;
	o[2] = addr / 0x100 % 0x100;
	o[3] = addr % 0x100;
	sprintf( addr_str, "%d.%d.%d.%d", o[3], o[2], o[1], o[0] );
}
