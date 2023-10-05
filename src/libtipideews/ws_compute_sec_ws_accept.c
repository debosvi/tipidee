/* ISC license. */

#include <tipidee/ws.h>
#include <skalibs/sha1.h>

#define ACC_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define ACC_UUID_SIZE 36

static const char encode_orig[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const char encode_url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

static int b64_encode_length(const int n) {
    return (((n + 3 - 1) / 3) * 4);
}

static int _b64_encode_string(const char *encode,
                              const char *in, int in_len,
                              char *out, int out_size) {
    unsigned char triple[3];
    int i, done = 0;

    while (in_len) {
        int len = 0;
        for (i = 0; i < 3; i++) {
            if (in_len) {
                triple[i] = (unsigned char) *in++;
                len++;
                in_len--;
            }
            else
                triple[i] = 0;
        }

        if (done + 4 >= out_size)
            return -1;

        *out++ = encode[triple[0] >> 2];
        *out++ = encode[(((triple[0] & 0x03) << 4) & 0x30) |
                        (((triple[1] & 0xf0) >> 4) & 0x0f)];
        *out++ =
            (char) (len >
                    1 ? encode[(((triple[1] & 0x0f) << 2) & 0x3c) |
                               (((triple[2] & 0xc0) >> 6) & 3)] : '=');
        *out++ = (char) (len > 2 ? encode[triple[2] & 0x3f] : '=');

        done += 4;
    }

    if (done + 1 >= out_size)
        return -1;

    *out++ = '\0';

    return done;
}

int b64_encode_string(const char *in, int in_len, char *out, int out_size) {
    return _b64_encode_string(encode_orig, in, in_len, out, out_size);
}

int b64_encode_string_sa(const char *in, int in_len, stralloc * out) {
    int n = b64_encode_length(in_len);
    stralloc_ready(out, n);
    int r = _b64_encode_string(encode_orig, in, in_len, out->s, out->a);
    out->len = r;
    return r;
}

int b64_encode_string_url(const char *in, int in_len, char *out,
                          int out_size) {
    return _b64_encode_string(encode_url, in, in_len, out, out_size);
}

int b64_encode_string_url_sa(const char *in, int in_len, stralloc * out) {
    int n = b64_encode_length(in_len);
    stralloc_ready(out, n);
    int r = _b64_encode_string(encode_url, in, in_len, out->s, out->a);
    out->len = r;
    return r;
}

int ws_compute_sec_ws_accept(char const *key, const size_t size,
                         stralloc * sa) {
    #define HASH_SIZE (20)
    unsigned char hash[HASH_SIZE];
    int n;

    SHA1Schedule sha1 = SHA1_INIT();
    sha1_update(&sha1, key, size);
    sha1_update(&sha1, ACC_UUID, ACC_UUID_SIZE);
    sha1_final(&sha1, (void *) hash);

    LOLDEBUG("key: %s", key);
    LOLDEBUG("sha1: (%d)%s", HASH_SIZE, hash);

    n = b64_encode_string_sa((char *) hash, HASH_SIZE, sa);

    LOLDEBUG("base64: (%d)%s", n, sa->s);

    return 1;
}
