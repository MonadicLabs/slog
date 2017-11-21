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

typedef struct slog_error_report
{

    char expected_hmac[128];
    char computed_hmac[128];
    char plain_text_entry[1024];
    int line_number;

} slog_error_report_t;

slog_t * slog_new(char * file_path, slog_key_t *secret_key);
slog_t * slog_open(char * file_path, slog_key_t *secret_key);
void slog_close( slog_t* s );

void slog_store( char * plain_text, slog_t *ctx );

int slog_validate(char *file_path, slog_key_t *secret_key, slog_error_report_t errors[], int errors_size );

void __advance( slog_t* ctx );
int __countlines(char* filename );
void strip(char *s);

slog_t * slog_init( slog_key_t* secret_key );

#endif
