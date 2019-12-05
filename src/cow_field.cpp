/*
 */

/* 
 * File:   cow_field.cpp
 * Author: Parfait Tokponnon <parfait.tokponnon@uclouvain.be>
 * 
 * Created on 3 décembre 2019, 15:13
 */

#include "cow_field.hpp"
#include "config.hpp"
#include "pd.hpp"
#include "hip.hpp"
Slab_cache Cow_field::cache(sizeof (Cow_field), 32);

Cow_field::Cow_field(Paddr phys, mword virt){
    cow_bit_field = reinterpret_cast<mword*>(Buddy::allocator.alloc(1, Pd::kern.quota, Buddy::FILL_0));
    phys_cow_bit_field = reinterpret_cast<mword*>(Buddy::allocator.alloc(1, Pd::kern.quota, Buddy::FILL_0));
    phys_mem_block_index = phys >> (FIELD_BITS + PAGE_BITS);
    mem_block_index = virt >> (FIELD_BITS + PAGE_BITS);
}

Cow_field::~Cow_field() {
    Buddy::allocator.free(reinterpret_cast<mword>(cow_bit_field), Pd::kern.quota);
    Buddy::allocator.free(reinterpret_cast<mword>(phys_cow_bit_field), Pd::kern.quota);
}

ALWAYS_INLINE
inline void* Cow_field::operator new (size_t) {return cache.alloc(Pd::kern.quota);}

void Cow_field::operator delete (void *ptr) { cache.free (ptr, Pd::kern.quota); }

void Cow_field::set_cow(Queue<Cow_field> *cow_fields, Paddr phys, mword virt) {
    phys &= ~(PAGE_MASK | Hpt::HPT_NX); // normalize p
    virt &= ~PAGE_MASK;
    Cow_field *c = cow_fields->head(), *tail = cow_fields->tail(), *next = nullptr;
    while(c) {
        if(c->set_cow(phys, virt))
            return;
        next = c->next; 
        c = (c == tail) ? nullptr : next;          
    }
    // No existing cow_field, create a new one.
    c = new Cow_field(phys, virt);
    c->set_cow(phys, virt);
    cow_fields->enqueue(c);
}

bool Cow_field::set_cow(Paddr phys, mword virt){
    size_t phys_mbi = phys >> (FIELD_BITS + PAGE_BITS), mbi = virt >> (FIELD_BITS + PAGE_BITS);
    if(phys_mbi != phys_mem_block_index) {
        asm volatile ("" ::"m" (mbi)); // to avoid gdb "optimized out"            
        return false;
    }
    size_t phys_index_in_cowfield = (phys >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1),
            index_in_cowfield = (virt >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1);
    mword* phys_cbf = phys_cow_bit_field + phys_index_in_cowfield, *cbf = cow_bit_field + index_in_cowfield; 
    size_t phys_offset_in_cowfield = (phys >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1), 
            offset_in_cowfield = (virt >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1);
    *phys_cbf |= (1ull << phys_offset_in_cowfield); 
    *cbf |= (1ull << offset_in_cowfield); 
    return true;
}

bool Cow_field::is_cowed(Queue<Cow_field> *cow_fields, Paddr phys, mword virt){
    Cow_field *c = cow_fields->head(), *tail = cow_fields->tail(), *next = nullptr;
    bool is_cow_field = false;
    while(c) {
        if(c->is_cowed(phys, virt, is_cow_field))
            return true;
        if(is_cow_field)
            return false;
        next = c->next; 
        c = (c == tail) ? nullptr : next;          
    }
    return false;
}

bool Cow_field::is_cowed(Paddr phys, mword virt, bool& is_cow_field){
    size_t phys_mbi = phys >> (FIELD_BITS + PAGE_BITS), mbi = virt >> (FIELD_BITS + PAGE_BITS);;
    if(phys_mbi != phys_mem_block_index) {
        asm volatile ("" ::"m" (mbi)); // to avoid gdb "optimized out"            
        return false;
    }
    size_t phys_index_in_cowfield = (phys >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1),
            index_in_cowfield = (virt >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1);
    mword* phys_cbf = phys_cow_bit_field + phys_index_in_cowfield, 
            *cbf = cow_bit_field + index_in_cowfield; 
    size_t phys_offset_in_cowfield = (phys >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1),
            offset_in_cowfield = (virt >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1);
    is_cow_field = true;
    asm volatile ("" ::"m" (offset_in_cowfield)); // to avoid gdb "optimized out"            
    asm volatile ("" ::"m" (cbf)); // to avoid gdb "optimized out"            
    return (*phys_cbf & (1ull << phys_offset_in_cowfield));  
}
