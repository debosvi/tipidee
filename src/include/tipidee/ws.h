/* ISC license. */

#ifndef TIPIDEE_WS_H
#define TIPIDEE_WS_H

#include <tipidee/headers.h>

#include <skalibs/stralloc.h>

#define DEBUG
#include <skalibs/lolstdio.h>

// main features
extern int ws_manage_websocket(tipidee_headers const* hdr, tain const *readtto, tain const *writetto);
extern int ws_handshake(char const* key, tain const *writetto);
extern int ws_mainstream(tain const *readtto, tain const *writetto);

// other features
extern int ws_compute_sec_ws_accept (char const *, const size_t, stralloc *);
extern int ws_exec_helper (char const *, const size_t);


extern void ws_data_mask(stralloc* dest, stralloc const *masked, char const* mask);

#endif
