#ifndef SLOG_H
#define SLOG_H

#include <stdint.h>
#include <stdio.h>

#include "slog_config.h"
#include "key.h"

typedef enum slog_output_type
{
    SLOG_OUTPUT_FILE = 0,
    SLOG_OUTPUT_MEM
} slog_output_type_t;

typedef struct slog
{

    char *              file_path;
    uint8_t *           next_s;
    int                 next_s_size;
#ifdef SLOG_HAVE_FILESYSTEM_SUPPORT
    FILE*               _file;
#else
    void *              _output;
    int                 _outputsize;
#endif
    slog_output_type_t  type;

} slog_t;

typedef struct slog_error_report
{

    char expected_hmac[128];
    char computed_hmac[128];
    char plain_text_entry[1024];
    int line_number;

} slog_error_report_t;

#ifdef SLOG_HAVE_FILESYSTEM_SUPPORT
slog_t * slog_new_file(char * file_path, slog_key_t *secret_key);
slog_t * slog_open_file(char * file_path, slog_key_t *secret_key);
int slog_validate_file(char *file_path, slog_key_t *secret_key, slog_error_report_t errors[], int errors_size );
int __countlines(char* filename );
#endif

slog_t * slog_init( slog_key_t* secret_key );
slog_t * slog_new( void* output_buffer, int buffer_size, slog_key_t* secret_key );
void slog_close( slog_t* s );
int slog_store( char * plain_text, slog_t *ctx );

void __advance( slog_t* ctx );
void strip(char *s);

#endif
