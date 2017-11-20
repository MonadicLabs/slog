
#include <stdio.h>

#include <slog.h>

int main( int argc, char** argv )
{
    foo();

    slog_key_t * key = slog_key_new( "novadempscouille" );
    void * poo = 0;

    /*
    if( atoi(argv[1]) == 0 )
        poo = slog_new( "/tmp/couille.txt", key );
    else if( atoi(argv[1]) == 1 )
        poo = slog_open( "/tmp/couille.txt", key );
    int k = 0;
    for( k = 0; k < 100; ++k )
        slog_store( "ENCULEZdkgfkfdjglk", poo );

    */

    int num_errors;
    key = slog_key_new( "novadempscouille" );
    slog_validate( "/tmp/couille.txt", key );

    printf( "num_errors=%d\n", num_errors );
    /*
    int j = 0;
    for( j = 0; j < num_errors; ++j )
    {
        printf( "Found eroneous entry in line: %d \n", errors[j] );
    }
    */

    return 0;
}
