/* ISC license. */

#include <tipidee/ws.h>

// mask is implictely 4 bytes wide
void ws_data_mask(stralloc* dest, stralloc const* masked, char const* mask) {
    stralloc_copy(dest, masked);

    for(int i=0; i<dest->len; i++) {
        dest->s[i] = dest->s[i] ^mask[i%4];
    }
}
