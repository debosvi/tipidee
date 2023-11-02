/* ISC license. */

#include <tipidee/ws.h>
#include <tipidee/base64.h>
#include <skalibs/sha1.h>

#define ACC_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define ACC_UUID_SIZE 36

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
