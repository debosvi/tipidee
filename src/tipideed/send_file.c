/* ISC license. */

#include <skalibs/sysdeps.h>

#ifdef SKALIBS_HASSPLICE

#include <skalibs/nonposix.h>

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>
#include <skalibs/unix-timed.h>

#include "tipideed-internal.h"

void init_splice_pipe (void)
{
  if (pipenbcoe(g.p) == -1)
    strerr_diefu1sys(111, "pipe2") ;
}

struct spliceinfo_s
{
  ssize_t n ;
  uint32_t last : 1 ;
} ;

static int getfd (void *b)
{
  (void)b ;
  return 1 ;
}

static int isnonempty (void *b)
{
  struct spliceinfo_s *si = b ;
  return !!si->n ;
}

static int flush (void *b)
{
  struct spliceinfo_s *si = b ;
  while (si->n)
  {
    ssize_t r = splice(g.p[0], 0, 1, 0, si->n, SPLICE_F_NONBLOCK | (si->last ? 0 : SPLICE_F_MORE)) ;
    if (r == -1) return 0 ;
    if (!r) return 1 ;
    si->n -= r ;
  }
  return 1 ;
}

void send_file (int fd, uint64_t n, char const *fn)
{
  tain deadline ;
  struct spliceinfo_s si = { .last = 0 } ;
  tain_add_g(&deadline, &g.writetto) ;
  if (!buffer_timed_flush_g(buffer_1, &deadline))
    strerr_diefu2sys(111, "write", " to stdout") ;
  while (n)
  {
    si.n = splice(fd, 0, g.p[1], 0, n, 0) ;
    if (si.n == -1) strerr_diefu2sys(111, "read from ", fn) ;
    else if (!si.n) strerr_diefu3x(111, "serve ", fn, ": file was truncated") ;
    else if (si.n > n)
    {
      si.n = n ;
      if (g.verbosity >= 2)
        strerr_warnw2x("serving elongated file: ", fn) ;
    }
    n -= si.n ;
    if (!n) si.last = 1 ;
    tain_add_g(&deadline, &g.writetto) ;
    if (!timed_flush_g(&si, &getfd, &isnonempty, &flush, &deadline))
      strerr_diefu2sys(111, "splice", " to stdout") ;
  }
}

#else

#include <sys/uio.h>

#include <skalibs/allreadwrite.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/tai.h>

#include "tipideed-internal.h"

void init_splice_pipe (void)
{
}

void send_file (int fd, uint64_t n, char const *fn)
{
  tain deadline ;
  struct iovec v[2] ;
  while (n)
  {
    ssize_t r ;
    buffer_rpeek(buffer_1, v) ;
    r = allreadv(fd, v, 2) ;
    if (r > n)
    if (r == -1) strerr_diefu2sys(111, "read from ", fn) ;
    if (!r) strerr_diefu3x(111, "serve ", fn, ": file was truncated") ;
    if (r > n)
    {
      r = n ;
      if (g.verbosity >= 2)
        strerr_warnw2x("serving elongated file: ", fn)
    }
    buffer_rseek(b, r) ;
    tain_add_g(&deadline, g.writetto) ;
    if (!buffer_timed_flush_g(buffer_1, &deadline))
      strerr_diefu1sys(111, "write to stdout") ;
    n -= r ;
  }
}

#endif