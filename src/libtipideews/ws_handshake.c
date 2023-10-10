/* ISC license. */

#include <tipidee/ws.h>

#include <skalibs/unix-timed.h>

int ws_handshake(char const* key, tain const* writetto) {
    stralloc sa = STRALLOC_ZERO;
    if(!ws_compute_sec_ws_accept(key, strlen(key), &sa))
        strerr_diefu1sys(111, "compute Sec-WebSocket-Accept");

    buffer_putsnoflush(buffer_1, "HTTP/1.1 101 Switching Protocols\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Upgrade: WebSocket\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Connection: Upgrade\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Sec-WebSocket-Accept: ");
    buffer_putnoflush(buffer_1, sa.s, sa.len);
    buffer_putsnoflush(buffer_1, "\x0d\x0a");
    // buffer_putsnoflush(buffer_1, "Sec-WebSocket-Version: 5\x0d\x0a");
    // buffer_putsnoflush(buffer_1, "Sec-WebSocket-Extension: mux\x0d\x0a");
    // buffer_putsnoflush(buffer_1, "Sec-WebSocket-Protocol: websocket\x0d\x0a");
    buffer_putsnoflush(buffer_1, "\x0d\x0a");

    {
        tain deadline;
        tain_add_g(&deadline, writetto);
        if (!buffer_timed_flush_g(buffer_1, &deadline))
            strerr_diefu1sys(111, "write to stdout");
    }

    stralloc_free(&sa);
    return 1;
}
