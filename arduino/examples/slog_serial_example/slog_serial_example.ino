#include <key.h>
#include <slog.h>
#include <mac.h>
#include <getline.h>
#include <slog_config.h>

slog_t * myslog;
char * popo;

#define RAND_STRING_LEN 32
char rand_string[ RAND_STRING_LEN  ];

void setup() {
  // put your setup code here, to run once:
  popo = (char*)malloc( 1024 );
  slog_key_t * key = slog_key_new( "myslogkey" );
  myslog = slog_new( popo, 1024, key );
  Serial.println( (int)myslog );
  Serial.begin(38400);
}

void loop() {
  
  for( int i = 0; i < RAND_STRING_LEN  - 1; ++i )
  {
    rand_string[i] = 'a' + rand() % 25;
  }
  rand_string[RAND_STRING_LEN  - 1] = 0;

  uint32_t ts1 = millis();
  int outLineSize = slog_store( rand_string, myslog );
  uint32_t ts2 = millis();
  // Serial.write( popo, outLineSize );
  // Serial.println( (int)myslog );
  Serial.println( ts2-ts1 );
  Serial.println( popo );
  delay(1000);
  
}
