
#include "block.h"

int slog_block_compute_hash(slog_block_t *block, uint8_t **hash, uint32_t *hash_size)
{
    int ret = -1;
    switch( block->block_type )
    {
    case SLOG_BLOCK_TYPE_DATA:
    {
        slog_data_block_t * dblock = (slog_data_block_t*)(block);
        ret = __slog_data_block_compute_hash( dblock, hash, hash_size );
        break;
    }

    case SLOG_BLOCK_TYPE_HEADER:
    {
        slog_header_block_t * hblock = (slog_header_block_t*)(block);
        ret = __slog_header_block_compute_hash( hblock, hash, hash_size );
        break;
    }

    default:
        break;
    }
    return ret;
}

int __slog_header_block_compute_hash(slog_block_t *block, uint8_t **hash, uint32_t *hash_size)
{
    uint8_t* base_hash;
    uint32_t base_hash_size;
    if( __compute_hash( ))
    return -1;
}

int __slog_data_block_compute_hash(slog_data_block_t *block, uint8_t **hash, uint32_t *hash_size)
{
    return -1;
}


int __compute_hash(uint8_t *data, uint32_t data_size, uint8_t **hash_value, uint32_t hash_size)
{
    return -1;
}


int __slog_base_block_compute_hash(slog_block_t *block, uint8_t **hash, uint32_t *hash_size)
{

}
