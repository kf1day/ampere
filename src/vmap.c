#include <stdlib.h>
#include <stdint.h>
#include "../inc/vmap.h"


void vmap_init( vmap_t **vmap ) {
	*vmap = calloc( 1, sizeof( vmap_t ) );
}

int vmap_get( vmap_t *vmap, uint32_t addr ) {
	uint16_t i;

	for ( i = 0; i < VMAP_SZ; i++ ) {
		if ( vmap->item[i].addr == addr ) {
			return i;
		}
	}
	i = vmap->index;
	if ( i < VMAP_SZ ) {
		if ( vmap->item[i].next == 0 ) {
			vmap->index++;
		} else {
			vmap->index = vmap->item[i].next;
		}
		vmap->item[i].addr = addr;
		vmap->item[i].penalty = 0;
		vmap->item[i].next = 0;
		return i;
	} else {
		return -2;
	}

}

int vmap_del( vmap_t *vmap, uint16_t index ) {

	if ( 0 <= index && index < VMAP_SZ ) {
		vmap->item[index].addr = 0;
		vmap->item[index].next = vmap->index;
		vmap->index = index;
		return 0;
	} else {
		return -1;
	}
}

