#include "slog.h"
#include "mac.h"
#include "slog_config.h"
#include "getline.h"

#include <stdio.h>
#include <string.h>

#include <mbedtls/sha512.h>
#include <mbedtls/base64.h>

#define min(X,Y) ((X) < (Y) ? (X) : (Y))

#ifdef SLOG_HAVE_FILESYSTEM_SUPPORT
slog_t *slog_new_file(char *file_path, slog_key_t* secret_key )
{
    slog_t * s = slog_init( secret_key );

    // Delete secret_key immediatly from memory
    slog_key_free( secret_key );

    // Copy file name
    s->file_path = (char*)malloc( strlen(file_path) );
    strcpy( s->file_path, file_path );

    // Check if file exists

    // If it does not, create it. Store fd
    s->_file = fopen( s->file_path, "w" );

    //
    s->type = SLOG_OUTPUT_FILE;

    return s;
}

slog_t *slog_open_file(char *file_path, slog_key_t *secret_key)
{
    slog_t * s = slog_init( secret_key );

    // Delete secret_key immediatly from memory
    slog_key_free( secret_key );

    // Copy file name
    s->file_path = (char*)malloc( strlen(file_path) );
    strcpy( s->file_path, file_path );

    // Check if file exists

    // Count existing lines
    int lines = __countlines( s->file_path );

    // If it does not, create it. Store fd
    s->_file = fopen( s->file_path, "r+" );

    // Check if it's the first store...
    fseek( s->_file, 0, SEEK_END );

    int j = 0;
    for( j = 0; j < lines; ++j )
    {
        __advance( s );
    }

    return s;
}

int slog_validate_file(char *file_path, slog_key_t *secret_key, slog_error_report_t errors[], int errors_size )
{

    FILE *fp = fopen( file_path, "r" );

    char *line = NULL;
    size_t len = 0;
    unsigned int read;

    slog_t * vs = slog_init( secret_key );

    int error_cpt = 0;
    int line_num = 0;

    while ((read = geetline(&line, &len, fp)) != -1)
    {
        char * e = strchr(line, '|');
        int index = (int)(e - line);
        if( index > 0 )
        {
            char * e2 = strchr(line, '\n');
            int index2 = (int)(e2 - line) + 1;
            int plain_text_len = index2 - index;
            unsigned char * plain_text = (unsigned char*)malloc( plain_text_len );
            memset( plain_text, 0, plain_text_len );
            memcpy( plain_text, line + index + 1, plain_text_len - 2 );
            unsigned char * computed_hmac = hmac( vs->next_s, plain_text );
            unsigned char hmac_b64[128];
            size_t olen;
            mbedtls_base64_encode( hmac_b64, 128, &olen, computed_hmac, 64 );

            // Now retrieve the stored HMAC
            unsigned char * stored_hmac = (unsigned char*)malloc( 128 );
            memset( stored_hmac, 0, 128 );
            memcpy( stored_hmac, line, 88 );

            int diff = memcmp( stored_hmac, hmac_b64, SLOG_RETAINED_HMAC_LEN );
            if( diff != 0 )
            {
                slog_error_report_t * rep = &(errors[ error_cpt++ ]); // = line_num + 1;
                memset( rep->expected_hmac, 0, SLOG_RETAINED_HMAC_LEN + 1 );
                memset( rep->computed_hmac, 0, SLOG_RETAINED_HMAC_LEN + 1 );
                memcpy( rep->expected_hmac, stored_hmac, SLOG_RETAINED_HMAC_LEN );
                memcpy( rep->computed_hmac, hmac_b64, SLOG_RETAINED_HMAC_LEN );
                memset( rep->plain_text_entry, 0, 1024 );
                memcpy( rep->plain_text_entry, plain_text, min( strlen((const char*)plain_text), 1023 ) );
                rep->line_number = line_num + 1;
            }

            free( plain_text );
            free( computed_hmac );

            line_num++;

            __advance( vs );

        }
    }

    free(line);
    return error_cpt;

}

int __countlines(char* filename)
{

    FILE *fileHandle;

    if ((fileHandle = fopen(filename, "r")) == NULL) {
        return -1;
    }

    char *line = NULL;
    int line_num = 0;
    size_t len = 0;
    unsigned int read;

    while ((read = geetline(&line, &len, fileHandle)) != -1)
    {
        char * e = strchr(line, '|');
        int index = (int)(e - line);
        if( index > 0 )
        {
            line_num++;
        }
    }

    free( line );
    fclose(fileHandle);

    return line_num;
}
#endif

int slog_store(char *plain_text, slog_t *ctx)
{
    int retc = -1;

    strip( plain_text );

    unsigned char * hmac_s = hmac( (unsigned char*)ctx->next_s, (unsigned char*)plain_text );

    unsigned char b64out[ 1024 ];
    size_t olen;
    int ret = mbedtls_base64_encode( b64out, 1024, &olen, hmac_s, 64 );
    memset( b64out + SLOG_RETAINED_HMAC_LEN, 0, olen - SLOG_RETAINED_HMAC_LEN );

#ifdef SLOG_HAVE_FILESYSTEM_SUPPORT
    if( ctx->type == SLOG_OUTPUT_FILE )
    {
        retc = fprintf( ctx->_file, "%s|%s\n", b64out, plain_text );
    }
    else
    {
        // error !
    }
#else
    if( ctx->type == SLOG_OUTPUT_MEM )
    {
        retc = sprintf( (char*)ctx->_output, "%s|%s", b64out, plain_text );
    }
    else
    {
        // error !
    }
#endif

    free( hmac_s );

    // Advance Sk
    __advance( ctx );

    return retc;

}

void __advance(slog_t *ctx)
{
    // Sk becomes sha256( Sk )
    unsigned char temp[64];
    mbedtls_sha512( ctx->next_s, ctx->next_s_size, temp, 0 );
    memcpy( ctx->next_s, temp, 64 );
}

slog_t *slog_init(slog_key_t *secret_key)
{
    slog_t * s = (slog_t*)malloc( sizeof( slog_t ) );

    // Create first hash of secret key
    s->next_s = (uint8_t*)malloc( 64 );
    mbedtls_sha512( secret_key->data, secret_key->len, s->next_s, 0 );
    s->next_s_size = 64;

    return s;
}

void slog_close(slog_t *s)
{
#ifdef SLOG_HAVE_FILESYSTEM_SUPPORT
    if( s->type == SLOG_OUTPUT_FILE )
        fclose( s->_file );
#endif
    free( s->file_path );
    free( s->next_s );
}

void strip(char *s) {
    char *p2 = s;
    while(*s != '\0') {
        if(*s != '\t' && *s != '\n') {
            *p2++ = *s++;
        } else {
            ++s;
        }
    }
    *p2 = '\0';
}

slog_t *slog_new(void *output_buffer, int buffer_size, slog_key_t *secret_key)
{
    slog_t * s = slog_init( secret_key );

    // Delete secret_key immediatly from memory
    slog_key_free( secret_key );

    s->type = SLOG_OUTPUT_MEM;

#ifndef SLOG_HAVE_FILESYSTEM_SUPPORT
    s->_output = output_buffer;
    s->_outputsize = buffer_size;
#endif

    return s;
}
