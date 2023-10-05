/* ISC license. */

#include <errno.h>

#include <tipidee/ws.h>

// waiting common API in lib
extern void log_and_exit (int) gccattr_noreturn ;

int ws_manage_websocket(tipidee_headers const *hdr, tain const *readtto, tain const *writetto) {
    char const *x;

    x = tipidee_headers_search(hdr, "Upgrade");
    if (x && !strncmp(x, "websocket", 9)) {
        x = tipidee_headers_search(hdr, "Sec-WebSocket-Key");
        if (x) {
            if(!ws_handshake(x, writetto))
                strerr_warnfu1sys("websocket handshake");

            LOLDEBUG("handshake success, wait commands");

            while(1) {
                int r=ws_mainstream(readtto, writetto);
                if(r<0)
                    log_and_exit(0);
                else if (!r)
                    continue;
                else {
                    if(errno == ETIMEDOUT)
                        continue;
                    LOLDEBUG("websocket parse data");
                }
            }

        }
        else {
            strerr_warnfu1sys("no websocket key provided");
        }
    }
    else {
        strerr_warnfu2sys("http upgrade %s not managed", x);
    }

    return 1;
}
