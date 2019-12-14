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

Cow_field::Cow_field(mword virt){
    cow_bit_field = reinterpret_cast<mword*>(Buddy::allocator.alloc(1, Pd::kern.quota, Buddy::FILL_0));
    mem_block_index = virt >> (FIELD_BITS + PAGE_BITS);
}

Cow_field::~Cow_field() {
    Buddy::allocator.free(reinterpret_cast<mword>(cow_bit_field), Pd::kern.quota);
}

ALWAYS_INLINE
inline void* Cow_field::operator new (size_t) {return cache.alloc(Pd::kern.quota);}

void Cow_field::operator delete (void *ptr) { cache.free (ptr, Pd::kern.quota); }

void Cow_field::set_cow(Queue<Cow_field> *cow_fields, mword virt, bool enabled) {
    virt &= ~PAGE_MASK;
    Cow_field *c = cow_fields->head(), *h = c, *next = nullptr;
    while(c) {
        if(c->set_cow(virt, enabled, cow_fields))
            return;
        next = c->next; 
        c = (next == h) ? nullptr : next;          
    }
    // No existing cow_field, create a new one.
    c = new Cow_field(virt);
    c->set_cow(virt, enabled, cow_fields);
    cow_fields->enqueue(c);
}

bool Cow_field::set_cow(mword virt, bool enabled, Queue<Cow_field>* cow_fields){
    size_t mbi = virt >> (FIELD_BITS + PAGE_BITS);
    if(mbi != mem_block_index) {
        asm volatile ("" ::"m" (mbi)); // to avoid gdb "optimized out"            
        return false;
    }
    size_t index_in_cowfield = (virt >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1);
    mword *cbf = cow_bit_field + index_in_cowfield; 
    size_t offset_in_cowfield = (virt >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1);
    if(enabled) {
        if(!(*cbf & (1ull << offset_in_cowfield))) {
            *cbf |= (1ull << offset_in_cowfield);
            nb_cowed_page++;
        }
    } else if(*cbf & (1ull << offset_in_cowfield)) {
        *cbf &= ~(1ull << offset_in_cowfield);
        assert(nb_cowed_page);
        nb_cowed_page--;
        if(!nb_cowed_page) {
            cow_fields->dequeue(this);
            delete this;
        }
    }
    return true;
}

bool Cow_field::is_cowed(Queue<Cow_field> *cow_fields, mword virt){
    Cow_field *c = cow_fields->head(), *tail = cow_fields->tail(), *next = nullptr;
    bool is_cow_field = false;
    while(c) {
        if(c->is_cowed(virt, is_cow_field))
            return true;
        if(is_cow_field)
            return false;
        next = c->next; 
        c = (c == tail) ? nullptr : next;          
    }
    return false;
}

bool Cow_field::is_cowed(mword virt, bool& is_cow_field){
    size_t mbi = virt >> (FIELD_BITS + PAGE_BITS);;
    if(mbi != mem_block_index) {
        asm volatile ("" ::"m" (mbi)); // to avoid gdb "optimized out"            
        return false;
    }
    size_t index_in_cowfield = (virt >> (OFFSET_BIT + PAGE_BITS)) & ((1ull << (FIELD_BITS - OFFSET_BIT)) - 1);
    mword* cbf = cow_bit_field + index_in_cowfield; 
    size_t offset_in_cowfield = (virt >> PAGE_BITS) & ((1ull << OFFSET_BIT) - 1);
    is_cow_field = true;
    return (*cbf & (1ull << offset_in_cowfield));  
}
