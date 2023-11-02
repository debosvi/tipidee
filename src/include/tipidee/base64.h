/* ISC license. */

#ifndef BASE64_INTERNAL_H
#define BASE64_INTERNAL_H

#include <nettle/base64.h>

size_t b64_encode_string(const char* in, const size_t in_len, char *out, const size_t out_len);
size_t b64_encode_string_sa(const char* in, const size_t in_len, stralloc* const out);
size_t b64_encode_string_url(const char* in, const size_t in_len, char* out, const size_t out_len);
size_t b64_encode_string_url_sa(const char* in, const size_t in_len, stralloc* const out);

#endif
