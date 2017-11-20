
#include "key.h"

#include <mbedtls/sha512.h>

slog_key_t *slog_key_new(char *secret_password)
{
    slog_key_t * k = (slog_key_t*)malloc( sizeof( slog_key_t ) );
    k->data = malloc(64);
    mbedtls_sha512( secret_password, strlen(secret_password), k->data, 0 );
    k->len = 512 / 8;
    return k;
}

void slog_key_free(slog_key_t *key)
{
    free( key->data );
    free( key );
}
