/* ISC license. */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// #include <skalibs/posixplz.h>
#include <skalibs/env.h>
// #include <skalibs/uint16.h>
#include <skalibs/types.h>
// #include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>
#include <skalibs/sig.h>
// #include <skalibs/stat.h>
// #include <skalibs/stralloc.h>
// #include <skalibs/djbunix.h>
#include <skalibs/random.h>
#include <skalibs/unix-timed.h>
// #include <skalibs/lolstdio.h>

#include "tipideed-internal.h"

#define USAGE "ws-handshake-client [ -v verbosity ] [ -f cdbfile ]"
#define dieusage() strerr_dieusage(100, USAGE)

struct global_s g = GLOBAL_ZERO ;

static uint32_t get_uint32 (char const *key) {
	uint32_t n ;
	if (!tipidee_conf_get_uint32(&g.conf, key, &n))
		strerr_diefu2sys(102, "read config value for ", key) ;
	return n ;
}

static void inittto (tain *tto, char const *key) {
  uint32_t ms = get_uint32(key) ;
  if (ms) tain_from_millisecs(tto, ms) ;
  else *tto = tain_infinite_relative ;
}

int main (int argc, char const *const *argv, char const *const *envp) {
	char progstr[25 + PID_FMT] = "ws-handshake-client: pid " ;
	progstr[25 + pid_fmt(progstr + 25, getpid())] = 0 ;
	PROG = progstr ;

	{
		char const *conffile = TIPIDEE_SYSCONFPREFIX "tipidee.conf.cdb" ;
		int gotv = 0 ;
		subgetopt l = SUBGETOPT_ZERO ;

		for (;;) {
			int opt = subgetopt_r(argc, argv, "v:f:", &l) ;
			if (opt == -1) break ;
			switch (opt) {
				case 'v' :
				{
				  unsigned int n ;
				  if (!uint0_scan(l.arg, &n)) dieusage() ;
				  if (n > 7) n = 7 ;
				  g.verbosity = n ;
				  gotv = 1 ;
				  break ;
				}
				case 'f' : conffile = l.arg ; break ;

				default : dieusage() ;
			}
		}
		argc -= l.ind ; argv += l.ind ;

		g.envlen = env_len(envp) ;
		if (!tipidee_conf_init(&g.conf, conffile))
			strerr_diefu2sys(111, "find configuration in ", conffile) ;
		if (!gotv) g.verbosity = get_uint32("G:verbosity") ;
	}
	
	inittto(&g.readtto, "G:read_timeout");
	inittto(&g.writetto, "G:write_timeout");
	
	char const *x = getenv("PROTO") ;
	if(x && !strncmp(x, "TCP", 3) ) {
		buffer_0->fd = 6;
		buffer_1->fd = 7;
	}
	
	// fill request 
	buffer_putsnoflush(buffer_1, "GET ws://127.0.0.1:8080/test HTTP/1.1\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Host: 127.0.0.1:8080\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Connection: Upgrade\x0d\x0a");
    buffer_putsnoflush(buffer_1, "User-Agent: ws-handshake-client/1.0\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Upgrade: websocket\x0d\x0a");
    buffer_putsnoflush(buffer_1, "Sec-WebSocket-Version: 13\x0d\x0a");
    {
		char rd[16];
		random_devurandom (rd, 16);
		stralloc sa = STRALLOC_ZERO;
		int r=b64_encode_string_sa(rd, 16, &sa);
		buffer_putsnoflush(buffer_1, "Sec-WebSocket-Key: ");
		buffer_putnoflush(buffer_1, sa.s, r);
		buffer_putsnoflush(buffer_1, "\x0d\x0a");
		
	}
    buffer_putsnoflush(buffer_1, "Sec-WebSocket-Extension: permessage-deflate; client_max_window_bits\x0d\x0a");
    buffer_putsnoflush(buffer_1, "\x0d\x0a");

    {
        tain deadline;
        tain_add_g(&deadline, &g.writetto);
        if (!buffer_timed_flush_g(buffer_1, &deadline))
            strerr_diefu1sys(111, "write to stdout");
    }

	log_and_exit(0) ; 
}
