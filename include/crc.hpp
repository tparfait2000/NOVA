/*
 */

/* 
 * File:   crc.hpp
 * Author: Parfait Tokponnon <parfait.tokkponnon at uclouvain.be>
 *
 * Created on 7 juillet 2019, 18:33
 */

#pragma once
#include "types.hpp"
#include "compiler.hpp"


class Crc {
private:

    /* Tables for hardware crc that shift a crc by LONG and SHORT zeros. */
    static uint32 crc32c_long[4][256];
    static uint32 crc32c_short[4][256];
    static uint32 crc32c_table[8][256];

public:
    Crc();
    virtual ~Crc();
    
    static void initialize(void);
    static uint32 crc32c_shift(uint32[][256], uint32);
    static void crc32c_zeros(uint32 [][256], size_t );
    static void crc32c_zeros_op(uint32*, size_t);
    static void gf2_matrix_square(uint32*, uint32*);
    static uint32 gf2_matrix_times(uint32*, uint32);
    static uint32 compute(uint32, const void*, size_t);
};
