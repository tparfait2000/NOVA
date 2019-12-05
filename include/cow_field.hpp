/* 
 * File:   cow_field.hpp
 * Author: Parfait Tokponnon <parfait.tokponnon@uclouvain.be>
 *
 * Created on 3 décembre 2019, 15:13
 */

#pragma once

#include "queue.hpp"
#include "slab.hpp"

// FIELD_BIT = 16
// Si mword vaut 64 bits, il y a donc 2^16 / 64 = 2^16 / 2^6 = 1024 entrées dans un cow_field
// les 10 bits de poids fort constituent alors l'index tandis que les 6 bits de poids faible
// constituent l'offset.
#if     defined(__i386__)
#define OFFSET_BIT          5 
#elif   defined(__x86_64__)
#define OFFSET_BIT          6 
#endif

class Cow_field {
    friend class Queue<Cow_field>;
    static Slab_cache cache;
private:
    mword* cow_bit_field = nullptr, *phys_cow_bit_field = nullptr;
    size_t phys_mem_block_index = ~0ull, mem_block_index = ~0ull; // Such a block index does not exist; blocks span from 0 to 0xFFFFFFFFF
    Cow_field *prev = nullptr, *next = nullptr;

public:
    Cow_field(Paddr, mword);
    Cow_field(const Cow_field&);
    ~Cow_field();
    
    ALWAYS_INLINE
    static inline void *operator new (size_t);

    static void operator delete (void *ptr);
    
    Cow_field &operator=(Cow_field const &);
    
    static void set_cow(Queue<Cow_field>*, Paddr, mword);

    bool set_cow(Paddr, mword);
    
    static bool is_cowed(Queue<Cow_field>*, Paddr, mword);

    bool is_cowed(Paddr, mword, bool&);
};

