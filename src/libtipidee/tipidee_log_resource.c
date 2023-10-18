/* ISC license. */

#include <stddef.h>

#include <skalibs/strerr.h>

#include <tipidee/log.h>

void tipidee_log_resource (uint32_t v, tipidee_rql const *rql, char const *file, tipidee_resattr const *ra, char const *infopath)
{
  char const *a[10] = { PROG, ": info:" } ;
  size_t m = 2 ;
  if (!(v & TIPIDEE_LOG_RESOURCE)) return ;
  if (v & TIPIDEE_LOG_HOSTASPREFIX)
  {
    a[m++] = " host " ;
    a[m++] = rql->uri.host ;
  }
  a[m++] = " resource " ;
  a[m++] = file ;
  a[m++] = " type " ;
  a[m++] = ra->iscgi ? ra->isnph ? "nph" : "cgi" : ra->content_type ;
  if (ra->iscgi && infopath)
  {
    a[m++] = " path_info /" ;
    a[m++] = infopath ;
  }
  strerr_warnv(a, m) ;
}
