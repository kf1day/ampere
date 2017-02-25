#define VMAP_SZ 1024


typedef struct {
	uint16_t index;
	struct {
		uint32_t addr;
		uint8_t penalty;
		uint16_t next;
	} item[VMAP_SZ];
} vmap_t;


void vmap_init( vmap_t *vmap );
int vmap_get( vmap_t *vmap, uint32_t addr );
int vmap_del( vmap_t *vmap, uint16_t index );
