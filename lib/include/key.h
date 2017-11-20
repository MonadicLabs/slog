#ifndef KEY_H
#define KEY_H

#include <stdint.h>

typedef struct slog_key
{

    uint8_t *   data;
    int         len;

} slog_key_t;

slog_key_t * slog_key_new( char * secret_password );
void slog_key_free( slog_key_t* key );

#endif // KEY_H
