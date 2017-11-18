#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>

// Structure for slog entry, called block
//  _________________________________________________________
// | sequence_id | block_type | prev_block_hash | block_data |
//  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾

// Structure of HEADER block_data
//  _________________________________________________________
// | sequence_id | block_type | prev_block_hash | block_data |
//  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾

// Structure of DATA block_data
//  _________________________________________________________
// | sequence_id | block_type | prev_block_hash | block_data |
//  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾

typedef enum
{

    SLOG_BLOCK_TYPE_HEADER = 0,
    SLOG_BLOCK_TYPE_DATA,
    SLOG_BLOCK_TYPE_LAST

} slog_block_type_t;

typedef enum
{

    SLOG_ENCRYPTION_RSA = 0,
    SLOG_ENCRYPTION_LAST

} slog_encryption_type;

typedef struct slog_block
{

    uint32_t                seq_idx;
    slog_block_type_t       block_type;
    uint32_t                prev_block_hash_size;
    uint8_t *               prev_block_hash_data;

} slog_block_t;

typedef struct slog_header_block
{

    slog_block_t    base;

} slog_header_block_t;

typedef struct slog_data_block
{

    slog_block_t    base;

} slog_data_block_t;

// Functions
slog_header_block_t * slog_new_header_block();
slog_data_block_t * slog_new_data_block();

//
int slog_block_compute_hash( slog_block_t* block, uint8_t** hash, uint32_t* hash_size );

int __slog_base_block_compute_hash( slog_block_t* block, uint8_t** hash, uint32_t* hash_size );
int __slog_header_block_compute_hash( slog_block_t* block, uint8_t** hash, uint32_t* hash_size );
int __slog_data_block_compute_hash( slog_data_block_t* block, uint8_t** hash, uint32_t* hash_size );
int __compute_hash( uint8_t* data, uint32_t data_size, uint8_t** hash_value, uint32_t hash_size );

#endif
