/* ISC license. */

#include <skalibs/bsdsnowflake.h>
#include <skalibs/nonposix.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <skalibs/posixplz.h>
#include <skalibs/env.h>
#include <skalibs/uint16.h>
#include <skalibs/types.h>
#include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>
#include <skalibs/sig.h>
#include <skalibs/stat.h>
#include <skalibs/stralloc.h>
#include <skalibs/djbunix.h>
#include <skalibs/avltreen.h>
#include <skalibs/unix-timed.h>
#include <skalibs/lolstdio.h>

#include <tipidee/tipidee.h>
#include "tipideed-internal.h"

#define USAGE "websocketd [ -v verbosity ] [ -f cdbfile ] [ -d basedir ] [ -R ] [ -U ]"
#define dieusage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "stralloc_catb")

#define MAX_LOCALREDIRS 32
#define ARGV_MAX 128

struct global_s g = GLOBAL_ZERO ;

static void sigchld_handler (int sig)
{
  (void)sig ;
  wait_reap() ;
}

void log_and_exit (int e)
{
  tipidee_log_exit(g.logv, e) ;
  _exit(e) ;
}

static inline void prep_env (size_t *remoteip, size_t *remotehost)
{
  static char const basevars[] = "PROTO\0TCPCONNNUM\0GATEWAY_INTERFACE=CGI/1.1\0SERVER_SOFTWARE=tipidee/" TIPIDEE_VERSION ;
  static char const sslvars[] = "SSL_PROTOCOL\0SSL_CIPHER\0SSL_TLS_SNI_SERVERNAME\0SSL_PEER_CERT_HASH\0SSL_PEER_CERT_SUBJECT\0HTTPS=on" ;
  char const *x = getenv("SSL_PROTOCOL") ;
  size_t protolen ;
  if (sagetcwd(&g.sa) == -1) strerr_diefu1sys(111, "getcwd") ;
  if (g.sa.len == 1) g.sa.len = 0 ;
  g.cwdlen = g.sa.len ;
  if (!stralloc_readyplus(&g.sa, 220 + sizeof(basevars) + sizeof(sslvars))) dienomem() ;
  if (g.cwdlen) stralloc_0(&g.sa) ;
  stralloc_catb(&g.sa, basevars, sizeof(basevars)) ;
  if (x) stralloc_catb(&g.sa, sslvars, sizeof(sslvars)) ;
  g.ssl = !!x ;
  x = getenv(basevars) ;
  protolen = strlen(x) ;
  if (protolen > 1000) strerr_dieinvalid(100, "PROTO") ;
  if (!x) strerr_dienotset(100, "PROTO")  ;
  {
    size_t m ;
    ip46 ip ;
    uint16_t port ;
    char fmt[IP46_FMT] ;
    char var[protolen + 11] ;
    memcpy(var, x, protolen) ;

    memcpy(var + protolen, "LOCALPORT", 10) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!uint160_scan(x, &g.defaultport)) strerr_dieinvalid(100, var) ;
    if (!stralloc_catb(&g.sa, var, protolen + 10)
     || !stralloc_catb(&g.sa, "SERVER_PORT=", 12)) dienomem() ;
    m = uint16_fmt(fmt, g.defaultport) ; fmt[m++] = 0 ;
    if (!stralloc_catb(&g.sa, fmt, m)) dienomem() ;

    memcpy(var + protolen, "LOCALIP", 8) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!ip46_scan(x, &ip)) strerr_dieinvalid(100, var) ;
    if (!stralloc_catb(&g.sa, var, protolen + 8)
     || !stralloc_catb(&g.sa, "SERVER_ADDR=", 12)) dienomem() ;
    m = ip46_fmt(fmt, &ip) ; fmt[m++] = 0 ;
    if (!stralloc_catb(&g.sa, fmt, m)) dienomem() ;

    memcpy(var + protolen, "LOCALHOST", 10) ;
    x = getenv(var) ;
    if (x)
    {
      if (!stralloc_catb(&g.sa, var, protolen + 10)) dienomem() ;
      g.defaulthost = x ;
    }

    memcpy(var + protolen, "REMOTEPORT", 11) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!uint160_scan(x, &port)) strerr_dieinvalid(100, var) ;
    if (!stralloc_catb(&g.sa, var, protolen + 11)
     || !stralloc_catb(&g.sa, "REMOTE_PORT=", 12)) dienomem() ;
    m = uint16_fmt(fmt, port) ; fmt[m++] = 0 ;
    if (!stralloc_catb(&g.sa, fmt, m)) dienomem() ;

    memcpy(var + protolen, "REMOTEIP", 9) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!ip46_scan(x, &ip)) strerr_dieinvalid(100, var) ;
    if (!stralloc_catb(&g.sa, var, protolen + 9)
     || !stralloc_catb(&g.sa, "REMOTE_ADDR=", 12)) dienomem() ;
    *remoteip = g.sa.len ;
    m = ip46_fmt(fmt, &ip) ; fmt[m++] = 0 ;
    if (!stralloc_catb(&g.sa, fmt, m)) dienomem() ;

    memcpy(var + protolen, "REMOTEHOST", 11) ;
    x = getenv(var) ;
    if ((x && !stralloc_catb(&g.sa, var, protolen + 11))
     || !stralloc_catb(&g.sa, "REMOTE_HOST=", 12)) dienomem() ;
    *remotehost = g.sa.len ;
    if (x)
    {
      if (!stralloc_cats(&g.sa, x)) dienomem() ;
    }
    else
    {
      if (!stralloc_readyplus(&g.sa, m + 2)) dienomem() ;
      if (ip46_is6(&ip)) stralloc_catb(&g.sa, "[", 1) ;
      stralloc_catb(&g.sa, g.sa.s + *remoteip, m) ;
      if (ip46_is6(&ip)) stralloc_catb(&g.sa, "]", 1) ;
    }
    if (!stralloc_0(&g.sa)) dienomem() ;

    memcpy(var + protolen, "REMOTEINFO", 11) ;
    x = getenv(var) ;
    if (x)
      if (!stralloc_catb(&g.sa, var, protolen + 11)
       || !stralloc_catb(&g.sa, "REMOTE_IDENT=", 13)
       || !stralloc_cats(&g.sa, x) || !stralloc_0(&g.sa)) dienomem() ;
  }
}


static uint32_t get_uint32 (char const *key)
{
  uint32_t n ;
  if (!tipidee_conf_get_uint32(&g.conf, key, &n))
    strerr_diefu2sys(102, "read config value for ", key) ;
  return n ;
}

static void inittto (tain *tto, char const *key)
{
  uint32_t ms = get_uint32(key) ;
  if (ms) tain_from_millisecs(tto, ms) ;
  else *tto = tain_infinite_relative ;
}

																										   
 
					  
						  
					  
						
					
			 
				  
							
								
									  
								 
				  
	 
								
									  
								 
							  
														  
	 
 
								 
																										  
							
			
 

																												  
 
						 
																										  
																			   
																						  
																		  
																								   
				  
 

																		  
 
													
						   
								  
															   
											 
						  
						 
 

																																		   
 
											 
									   
										  
							
				  
												  
								   
												   
								

				  

									   
	 
													   
																							
																				
		  
	 
							 
				
	 

								 

						  
																	   
										   
			
	 
									
																	   
				   
									 
					
	   
					  
											   
															
																  
															 
	   
	 
							 
	 
						  
													   
															
											
	 
													   
													   
													   
													 
					  
	 
									  
																													 

									  

									  
									   
															
													  
														

									   
																		 

														

									 
																								 

															   
			   
										
						 
												
												
									
										
													  
 

int main (int argc, char const *const *argv, char const *const *envp)
{
  size_t remoteip, remotehost ;
  char const *x ;
  uint32_t n ;							   
				 
			  
  char progstr[14 + PID_FMT] = "tipideed: pid " ;
  progstr[14 + pid_fmt(progstr + 14, getpid())] = 0 ;
  PROG = progstr ;

  {
    char const *conffile = TIPIDEE_SYSCONFPREFIX "tipidee.conf.cdb" ;
	int gotv = 0 ;						 
    unsigned int h = 0 ;
    subgetopt l = SUBGETOPT_ZERO ;

    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "v:f:d:RU", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' :
        {
          unsigned int n ;
          if (!uint0_scan(l.arg, &n)) dieusage() ;
          if (n > 7) n = 7 ;
          g.logv = n ;
          break ;
        }
        case 'f' : conffile = l.arg ; break ;
        case 'R' : h |= 3 ; break ;
        case 'U' : h |= 1 ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;

    g.envlen = env_len(envp) ;
    if (!tipidee_conf_init(&g.conf, conffile))
      strerr_diefu2sys(111, "find configuration in ", conffile) ;
	if (!gotv) g.logv = get_uint32("G:logv") ;
  }

  prep_env(&remoteip, &remotehost) ;
  inittto(&g.readtto, "G:read_timeout") ;
  inittto(&g.writetto, "G:write_timeout") ;
  inittto(&g.cgitto, "G:cgi_timeout") ;
  g.maxrqbody = get_uint32("G:max_request_body_length") ;
  g.maxcgibody = get_uint32("G:max_cgi_body_length") ;
  n = tipidee_conf_get_argv(&g.conf, "G:index-file", g.indexnames, 16, &g.indexlen) ;
  if (!n) strerr_dief3x(102, "bad", " config value for ", "G:index_file") ;
  g.indexn = n-1 ;

  x = tipidee_conf_get_responseheaders(&g.conf, "G:response_headers", &n, &g.rhdrn) ;
  if (!x) strerr_diefu3sys(102, "get", " config value for ", "G:response_headers") ;

  tipidee_response_header rhdr[n ? n : 1] ;  /* should start a block but that's a lot of editing */
  if (!tipidee_response_header_preparebuiltin(rhdr, g.rhdrn, x, n))
    strerr_dief3x(102, "bad", " config value for ", "G:response_headers") ;
  g.rhdr = rhdr ;

  if (ndelay_on(0) == -1 || ndelay_on(1) == -1)
    strerr_diefu1sys(111, "set I/O nonblocking") ;
  if (!sig_catch(SIGCHLD, &sigchld_handler))
    strerr_diefu1sys(111, "set SIGCHLD handler") ;
  if (!sig_altignore(SIGPIPE))
    strerr_diefu1sys(111, "ignore SIGPIPE") ;
  if (!tain_now_set_stopwatch_g())
    strerr_diefu1sys(111, "initialize clock") ;


  tipidee_log_start(g.logv, g.sa.s + remoteip, g.sa.s + remotehost) ;


 /* Main loop */

  while (g.cont)
  {
    tain deadline ;
    tipidee_rql rql = TIPIDEE_RQL_ZERO ;
    tipidee_headers hdr ;
    int e ;
    // unsigned int localredirs = 0 ;
    char const *x ;
    size_t content_length ;
    tipidee_transfercoding tcoding = TIPIDEE_TRANSFERCODING_UNKNOWN ;
    char uribuf[URI_BUFSIZE] ;
    char hdrbuf[HDR_BUFSIZE] ;

    tain_add_g(&deadline, &g.readtto) ;
    

    e = tipidee_rql_read_g(buffer_0, uribuf, URI_BUFSIZE, &content_length, &rql, &deadline) ;
    switch (e)
    {
      case -1 : log_and_exit(1) ;  /* bad client */
      case 0 : break ;
      case 98 :  /* client exited */
      case 99 : g.cont = 0 ; continue ;  /* timeout */
      case 400 : eexit_400(&rql, "Syntax error in request line") ;
      default : strerr_dief2x(101, "can't happen: ", "unknown tipidee_rql_read return code") ;
    }
    if (rql.http_major != 1) log_and_exit(1) ;
    if (rql.http_minor > 1) eexit_400(&rql, "Bad HTTP version") ;

    content_length = 0 ;
    tipidee_headers_init(&hdr, hdrbuf, HDR_BUFSIZE) ;
    e = tipidee_headers_timed_parse_g(buffer_0, &hdr, &deadline) ;
    switch (e)
    {
      case -1 : log_and_exit(1) ;  /* connection issue, client timeout, etc. */
      case 0 : break ;
      case 400 : eexit_400(&rql, "Syntax error in headers") ;
      case 408 : eexit_408(&rql) ;  /* timeout */
      case 413 : eexit_413(&rql, hdr.n >= TIPIDEE_HEADERS_MAX ? "Too many headers" : "Too much header data") ;
      case 500 : strerr_dief2x(101, "can't happen: ", "avltreen_insert failed") ;
      default : strerr_dief2x(101, "can't happen: ", "unknown tipidee_headers_parse return code") ;
    }

    if (!rql.http_minor) g.cont = 0 ;
    else
    {
      x = tipidee_headers_search(&hdr, "Connection") ;
      if (x)
      {
        if (strcasestr(x, "close")) g.cont = 0 ;
        else if (strcasestr(x, "keep-alive")) g.cont = 2 ;
      }
    }

    x = tipidee_headers_search(&hdr, "Transfer-Encoding") ;
    if (x)
    {
      if (strcasecmp(x, "chunked")) eexit_400(&rql, "unsupported Transfer-Encoding") ;
      else tcoding = TIPIDEE_TRANSFERCODING_CHUNKED ;
    }
    else
    {
      x = tipidee_headers_search(&hdr, "Content-Length") ;
      if (x)
      {
        if (!size_scan(x, &content_length)) eexit_400(&rql, "Invalid Content-Length") ;
        else if (content_length) tcoding = TIPIDEE_TRANSFERCODING_FIXED ;
        else tcoding = TIPIDEE_TRANSFERCODING_NONE ;
      }
      else tcoding = TIPIDEE_TRANSFERCODING_NONE ;
    }

    if (tcoding != TIPIDEE_TRANSFERCODING_NONE && rql.m != TIPIDEE_METHOD_POST)
      eexit_400(&rql, "only POST requests can have an entity body") ;

    // websocket
    x = tipidee_headers_search(&hdr, "Connection") ;
    if (x && !strncmp(x, "Upgrade", 7))
    {
      int r=ws_manage_websocket(&hdr, &g.readtto, &g.writetto);
								
								
										 
								   
																	
			   
							   
													
																				   
																							 
																			 
	 

															   
		  
	 
								
      if(r) {
          strerr_warn("websocket management complete") ;
          log_and_exit(0);
				
      }
																	
						
	 
						   
	 
																  
										 
	 
													 
													

      eexit_400(&rql, "syntax error in websocket management") ;
	 
										 
				
    }
    // else {
    //   strerr_warnfu2sys("websocket connection %s not managed", x) ;
    // }
											  
													   
											  
							  
																				  

										 

					  
	   
										   
		 
																	 
																										 
																								 
		   
															 
										  
		   
									   
				 
		 
											 
		 
																					  
		   
																						 
																 
										  
		   
				 
		 
						 
	   


																					 

																	  
											 
																												  
	 
  }

  log_and_exit(0) ;
}
