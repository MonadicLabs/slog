
#include <stdio.h>

#include <slog.h>

#include "termcolor.h"

int main( int argc, char** argv )
{

    if( argc != 3 )
        return -1;

    slog_key_t * key = slog_key_new( argv[2] );

    slog_error_report_t errors[1024];
    int num_errors = slog_validate_file( argv[1], key, errors, 1024 );

    int j = 0;
    for( j = 0; j < num_errors; ++j )
    {
        slog_error_report_t rep = errors[j];
        printf( "LINE %d got ", rep.line_number );
        fgColor(RED);
        printf( "%s", rep.computed_hmac );
        fgColor(DEFAULT);
        printf( " but should have been " );
        fgColor(GREEN);
        printf( "%s", rep.expected_hmac );
        fgColor(DEFAULT);
        printf( "\n" );

        printf( "entry incriminated: ");
        textBold(TRUE);
        printf( "%s", rep.plain_text_entry );
        textBold(FALSE);
        printf("\n\n");
    }

    return 0;
}
