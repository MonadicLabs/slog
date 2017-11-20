#include "slog.h"
#include "mac.h"

#include <stdio.h>
#include <string.h>

#include <mbedtls/sha512.h>
#include <mbedtls/base64.h>

#include <heatshrink_encoder.h>

void foo()
{
    printf( "bar.\n" );
}

slog_t *slog_new(char *file_path, slog_key_t* secret_key )
{

    slog_t * s = slog_init( secret_key );

    // Copy file name
    s->file_path = (char*)malloc( strlen(file_path) );
    strcpy( s->file_path, file_path );

    // Check if file exists

    // If it does not, create it. Store fd
    s->_file = fopen( s->file_path, "w" );

    // Delete secret_key immediatly from memory
    slog_key_free( secret_key );

    return s;
}

void slog_store(char *plain_text, slog_t *ctx)
{
    // Check if it's the first store...
    fseek( ctx->_file, 0, SEEK_END );
    // printf( "fpos_A=%d\n", fpos );
    int fpos = ftell( ctx->_file );
    // printf( "file_pos=%d\n", fpos );

    if( fpos > 0 )
    {
        // We have stored last Sk at the end of the file in case of system failure before fclose()
        // So, we seek at fpos - 88 strlen( b64( 512 bits ) )
        fseek( ctx->_file, fpos - 88, SEEK_SET );
    }

    unsigned char mackey[ 64 ];
    memset( mackey, 0, 64 );
    int k = 0;
    for( k = 0; k < 64; ++k )
        mackey[k] ^= ctx->next_s[k];

    unsigned char * hmac_s = hmac( ctx->next_s, plain_text );

    // TEST HEATSHRINK
    // heatshrink_encoder* hse = heatshrink_encoder_alloc( 4, 2 );
    // heatshrink_encoder_sink( hse, hmac_s, )
    //

    unsigned char b64out[ 1024 ];
    size_t olen;
    int ret = mbedtls_base64_encode( b64out, 1024, &olen, hmac_s, 64 );
    fprintf( ctx->_file, "%s|%s\n", b64out, plain_text );
    // printf( "olen=%d\n", olen );

    // Save the Sk that has been used for last entry. And set Sk+1
    ret = mbedtls_base64_encode( b64out, 1024, &olen, ctx->next_s, 64 );
    fprintf( ctx->_file, "%s", b64out );

    // Advance Sk
    __advance( ctx );

}

void __advance(slog_t *ctx)
{
    // Sk becomes sha256( Sk )
    unsigned char temp[64];
    mbedtls_sha512( ctx->next_s, ctx->next_s_size, temp, 0 );
    memcpy( ctx->next_s, temp, 64 );
}

slog_t *slog_open(char *file_path, slog_key_t *secret_key)
{
    slog_t * s = (slog_t*)malloc( sizeof( slog_t ) );

    // Copy file name
    s->file_path = (char*)malloc( strlen(file_path) );
    strcpy( s->file_path, file_path );

    // Check if file exists

    // If it does not, create it. Store fd
    s->_file = fopen( s->file_path, "r+" );

    // Check if it's the first store...
    fseek( s->_file, 0, SEEK_END );
    // printf( "fpos_A=%d\n", fpos );
    int fpos = ftell( s->_file );
    // printf( "file_pos=%d\n", fpos );

    if( fpos > 0 )
    {
        // We have stored last Sk at the end of the file in case of system failure before fclose()
        // So, we seek at fpos - 88 strlen( b64( 512 bits ) )
        fseek( s->_file, fpos - 88, SEEK_SET );

        unsigned char b64_sk[ 88 ];
        int nread = fread( b64_sk, 1, 88, s->_file );
        if( nread == 88 )
        {
            size_t olen;
            s->next_s = malloc( 64 );
            s->next_s_size = 64;
            mbedtls_base64_decode( s->next_s, 64, &olen, b64_sk, 88 );
        }

        // Advance
        __advance( s );

        // Return valid slog
        return s;
    }
    else
    {
        // Error, or new ? :/
    }

    return 0;

}

void slog_validate(char *file_path, slog_key_t *secret_key )
{

    FILE *fp = fopen( file_path, "r" );

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    slog_t * vs = slog_init( secret_key );

    int cpt = 0;
    int k = 0;

    while ((read = getline(&line, &len, fp)) != -1)
    {
        char * e = strchr(line, '|');
        int index = (int)(e - line);
        if( index > 0 )
        {
            // printf( "delimiter pos: %d\n", index );
            char * e2 = strchr(line, '\n');
            int index2 = (int)(e2 - line) + 1;
            int plain_text_len = index2 - index;
            unsigned char * plain_text = malloc( plain_text_len );
            memset( plain_text, 0, plain_text_len );
            memcpy( plain_text, line + index + 1, plain_text_len - 2 );
            // printf( "retrieved message: #%s#\n", plain_text );
            unsigned char * computed_hmac = hmac( vs->next_s, plain_text );
            unsigned char hmac_b64[128];
            int olen;
            mbedtls_base64_encode( hmac_b64, 128, &olen, computed_hmac, 64 );

            // Now retrieve the stored HMAC
            unsigned char * stored_hmac = malloc( 128 );
            memset( stored_hmac, 0, 128 );
            memcpy( stored_hmac, line, 88 );

            int diff = memcmp( stored_hmac, hmac_b64, 88 );
            printf( "STORED: %s - COMPUTED: %s - DIFF: %d \n", stored_hmac, hmac_b64, diff );

//            free( stored_hmac );
//            free( computed_hmac );
//            free( plain_text );

            printf( "line_num: %i \n", k );
            /*
            if( diff > 0 )
            {
                printf( "FOUND ERROR ! ret=%d line_num=%d \n", 4, line_num );
                // int toto = line_num;
                // errors[ (*num_errors)++ ] = toto;
                // memcpy( errors + cpt, &line_num, sizeof(int) );
                // cpt++;
            }
            */

            k++;

            __advance( vs );

        }
    }

    free(line);

}


slog_t *slog_init(slog_key_t *secret_key)
{
    slog_t * s = (slog_t*)malloc( sizeof( slog_t ) );

    // Create first hash of secret key
    s->next_s = malloc( 64 );
    mbedtls_sha512( secret_key->data, secret_key->len, s->next_s, 0 );
    s->next_s_size = 64;

    return s;
}
