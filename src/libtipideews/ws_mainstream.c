/* ISC license. */

#include <tipidee/ws.h>

#include <skalibs/uint16.h>
#include <skalibs/unix-timed.h>

// waiting common API in lib
extern void log_and_exit (int) gccattr_noreturn ;

#define M_FIN(x) (x[0]>>7)
#define M_RSV(x) ((x[0]>>4)&0x7)
#define M_OPCODE(x) (x[0]&0xF)
#define M_MASK(x) ((x[1]>>7)&0x1)
#define M_SIZE(x) (x[1]&0x7F)

void debug_hdr(unsigned char const* hdr) {
    LOLDEBUG("header: %02x %02x", hdr[0], hdr[1]);
    LOLDEBUG("fin: %d", M_FIN(hdr));
    LOLDEBUG("opcode: %d", M_OPCODE(hdr));
    LOLDEBUG("mask: %d", M_MASK(hdr));
    LOLDEBUG("size: %d", M_SIZE(hdr));
}

typedef struct ws_stream_s ws_stream, *ws_stream_ref;
struct ws_stream_s {
	uint64 size;
	unsigned char mask_b;
	unsigned char opcode;
	unsigned char fin;
	unsigned char rsv;
	unsigned char mask_d[4];
};


int ws_mainstream(tain const *readtto, tain const *writetto) {
    tain deadline ;
    tain_add_g(&deadline, readtto) ;

    ws_stream stream;

    // step 0 read 2 1st byte
    // step 1 read size as 16 bits wide
    // step 2 read size as 64 bits wide
    // step 3 read mask if so
    // step 4 data
	// step 127 end

    int step=0;
    int cont=1;
    while(cont) {
        LOLDEBUG("step %d", step);
        switch(step) {
        case 0:
            unsigned char hdr[2];
            if(buffer_timed_get_g(buffer_0, (char*)hdr, 2, &deadline)) {
                debug_hdr(hdr);
                stream.opcode=M_OPCODE(hdr);
                stream.size=M_SIZE(hdr);
                stream.mask_b=M_MASK(hdr);

                if(stream.size==126) step=1;
                else if(stream.size==127) step=2;
                else step=3;
            }
            break;

        case 1:
			{
				uint16 s=0;
				if(buffer_timed_get_g(buffer_0, (char*)&s, 2, &deadline)) {
					stream.size=s;
					step=3;
				}
			}
            break;

        case 2:
			{
				uint64 s=0;
				if(buffer_timed_get_g(buffer_0, (char*)&s, 8, &deadline)) {
					stream.size=s;
					step=3;
				}
			}
            break;

        case 3:
            if(!stream.mask_b) {
            }
            else if(buffer_timed_get_g(buffer_0, (char*)stream.mask_d, 4, &deadline)) {
            }
            step=4;
            break;

        case 4:
            int i=stream.size;
            char c;
            while(i) {
                if(buffer_timed_get_g(buffer_0, &c, 1, &deadline)) {
                    i--;
                }
            }
            step=127;
            break;

         case 127:
            LOLDEBUG("end data receive");
            cont=0;
            break;

       default:
            LOLDEBUG("switch not managed");
            cont=0;
            break;
        }
    }
    LOLDEBUG("loop finished");

    return 1;
}
