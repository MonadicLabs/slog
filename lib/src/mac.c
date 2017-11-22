
#include "mac.h"

#include <stdlib.h>
#include <string.h>

#include <mbedtls/sha512.h>

#define ARRAY_CONCAT(TYPE, A, An, B, Bn) \
(TYPE *)array_concat((const void *)(A), (An), (const void *)(B), (Bn), sizeof(TYPE));

void *array_concat(const void *a, size_t an,
               const void *b, size_t bn, size_t s)
{
    char *p = (char*)malloc(s * (an + bn));
    memcpy(p, a, an*s);
    memcpy(p + an*s, b, bn*s);
    return p;
}

unsigned char * hmac( unsigned char* K, unsigned char* m )
{
    unsigned char opad[64];
    unsigned char ipad[64];
    int i = 0;
    for( i = 0; i < 64; ++i )
    {
        ipad[i] = 0x36 ^ K[i];
        opad[i] = 0x5c ^ K[i];
    }

    unsigned char * rightSide = ARRAY_CONCAT( unsigned char, ipad, 64, m, strlen( (const char*)m) );
    unsigned char hashInner[64];
    mbedtls_sha512( rightSide, 64 + strlen( (const char*)m ), hashInner, 0 );
    unsigned char * leftSide = ARRAY_CONCAT( unsigned char, opad, 64, hashInner, 64 );
    unsigned char * output = (unsigned char*) malloc(64);
    mbedtls_sha512( leftSide, 128, output, 0 );

    free( leftSide );
    free( rightSide );

    return output;

}
