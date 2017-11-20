#ifndef SLOG_H
#define SLOG_H

#include <stdint.h>
#include <stdio.h>

#include "key.h"

typedef struct slog
{

    char *      file_path;
    uint8_t *   next_s;
    int         next_s_size;
    FILE*       _file;

} slog_t;

slog_t * slog_new(char * file_path, slog_key_t *secret_key);
slog_t * slog_open(char * file_path, slog_key_t *secret_key);

void slog_store( char * plain_text, slog_t *ctx );

void slog_validate(char * file_path, slog_key_t* secret_key);

void __advance( slog_t* ctx );
slog_t * slog_init( slog_key_t* secret_key );

#endif
