
#include <slog.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main( int argc, char** argv )
{
    if( argc != 4 )
        return -1;

    slog_key_t * key = slog_key_new( argv[3] );
    slog_t * myslog = slog_new_file( argv[2], key );

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    FILE *fp = fopen( argv[1], "r" );
    while ((read = getline(&line, &len, fp)) != -1)
    {
        if( strlen(line) > 1 )
        slog_store( line, myslog );
    }

    fclose( fp );

    return 0;
}
