/* ISC license. */

#include <sys/types.h>
#include <math.h>
#include <string.h>

// #define USE_SSL_BIO

#ifdef USE_SSL_BIO
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#else
#include <stdio.h>
#endif

#include <tipidee/ws.h>
#include <skalibs/sha1.h>
#include <skalibs/lolstdio.h>

#define ACC_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define ACC_UUID_SIZE 36

#if !defined(USE_SSL_BIO)
static const char encode_orig[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz0123456789+/";

static int
_lws_b64_encode_string(const char *encode, const char *in, int in_len,
		       char *out, int out_size)
{
	unsigned char triple[3];
	int i, done = 0;

	while (in_len) {
		int len = 0;
		for (i = 0; i < 3; i++) {
			if (in_len) {
				triple[i] = (unsigned char)*in++;
				len++;
				in_len--;
			} else
				triple[i] = 0;
		}

		if (done + 4 >= out_size)
			return -1;

		*out++ = encode[triple[0] >> 2];
		*out++ = encode[(((triple[0] & 0x03) << 4) & 0x30) |
					     (((triple[1] & 0xf0) >> 4) & 0x0f)];
		*out++ = (char)(len > 1 ? encode[(((triple[1] & 0x0f) << 2) & 0x3c) |
					(((triple[2] & 0xc0) >> 6) & 3)] : '=');
		*out++ = (char)(len > 2 ? encode[triple[2] & 0x3f] : '=');

		done += 4;
	}

	if (done + 1 >= out_size)
		return -1;

	*out++ = '\0';

	return done;
}

static int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size)
{
	return _lws_b64_encode_string(encode_orig, in, in_len, out, out_size);
}
#else
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	(void)BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	(void)BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;
    return (0); //success
}

#endif


void compute_sec_ws_accept (char const *key, const size_t size, char *accept, int length)
{
  unsigned char hash[20];
  char tmp[size+ACC_UUID_SIZE+1];
  int n=snprintf(tmp, 1024, "%s%s", key, ACC_UUID);
  SHA1Schedule sha1 = SHA1_INIT();
  sha1_update (&sha1, tmp, n) ;
  // sha1_update (&sha1, ACC_UUID, ACC_UUID_SIZE) ;
  sha1_final (&sha1, (void *)hash) ;

  LOLDEBUG("key: %s", key);
  LOLDEBUG("sha1: (%d)%s", strlen((char*)hash), hash);
  // {
  //   char* hex = hex_to_string(hash, 20);
  //     LOLDEBUG("sha1 hex: (%d)%s", strlen((char*)hex), hex);
  //
  //   }
#if !defined(USE_SSL_BIO)
  n=lws_b64_encode_string((char*)hash, 20, accept, length );
#else
  char *enc;
  Base64Encode(hash, 20, &enc);
  n=strlen(enc);
  strncpy(accept, enc, length);
  free(enc);
#endif

  LOLDEBUG("base64: (%d)%s", n, accept);

}
