
#include <nettle/base64.h>
#include <skalibs/stralloc.h>

static size_t b64_encode(struct base64_encode_ctx* ctx, const char* in, const size_t in_len, char* const out) {
    size_t r = base64_encode_update(ctx, out, in_len, (uint8_t*)in);
	r += base64_encode_final(ctx, out+r);
    return r;
}

size_t b64_encode_string(const char* in, const size_t in_len, char *out, const size_t out_len) {
    if(BASE64_ENCODE_LENGTH(in_len) >= out_len)
		return 0;
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	size_t r = b64_encode(&ctx, in, in_len, out);
	return r;
}

size_t b64_encode_string_sa(const char* in, const size_t in_len, stralloc* const out) {
	struct base64_encode_ctx ctx;
	register size_t n = BASE64_ENCODE_LENGTH(in_len);
    stralloc_ready(out, n);
    base64_encode_init(&ctx);
	size_t r = b64_encode(&ctx, in, in_len, out->s);
    out->len = r;
    return r;
}

size_t b64_encode_string_url(const char* in, const size_t in_len, char* out, const size_t out_len) {
    if(BASE64_ENCODE_LENGTH(in_len) >= out_len)
		return 0;
	struct base64_encode_ctx ctx;
	base64url_encode_init(&ctx);
	size_t r = b64_encode(&ctx, in, in_len, out);
	return r;
}

size_t b64_encode_string_url_sa(const char* in, const size_t in_len, stralloc* const out) {
	struct base64_encode_ctx ctx;
	register size_t n = BASE64_ENCODE_LENGTH(in_len);
    stralloc_ready(out, n);
    base64url_encode_init(&ctx);
	size_t r = b64_encode(&ctx, in, in_len, out->s);
    out->len = r;
    return r;
}
