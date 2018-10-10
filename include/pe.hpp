/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.hpp
 * Author: parfait
 *
 * Created on 3 octobre 2018, 14:34
 */

#pragma once
#include "types.hpp"
#include "slab.hpp"
#include "compiler.hpp"
#include "queue.hpp"
#include "console.hpp"

class Pe {
    friend class Queue<Pe>;
    static Slab_cache cache;    
        
    
    static size_t number;
    char ec[str_max_length];
    char pd[str_max_length];
    mword rip;
    Pe* prev;
    Pe* next;
    size_t numero = 0;
    bool marked = false;
    uint64 retirement_counter = 0;
    mword instruction = 0;
public:
    /**
     * 
     * @param ec
     * @param pd
     * @param rip_value
     * @param counter
     */
    Pe(const char* ec, const char* pd, mword rip_value);
    Pe &operator = (Pe const &);

    enum Member_type{
        RETIREMENT_COUNTER = 0,
        REGISTER_RIP,
    };
    
    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

    ALWAYS_INLINE
    static inline void destroy (Pe *obj, Quota &quota) { obj->~Pe(); cache.free (obj, quota); }
    
    Pe(const Pe& orig);    
    ~Pe();
    
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pe* pe = static_cast<Pe*> (ptr);
        pe->~Pe();
        cache.free (ptr, quota);
    }

    char* GetEc_name() {
        return ec;
    }

    char* GetPd_name() {
        return pd;
    }

    uint64 GetRetirement_counter() const {
        return retirement_counter;
    }

    mword GetRip() const {
        return rip;
    }
    
    Pe* get_next(){
        return next;
    };
    
    void print(){
        if(marked){
            char num_to_str[20];
            if(retirement_counter < MAX_INSTRUCTION)
                Console::sprint(num_to_str, "%llu", retirement_counter);
            else
                Console::sprint(num_to_str, "%llx", retirement_counter);
            Console::print("Pe_state %s %s %lu %lx %s %lx", ec, pd, numero, rip, num_to_str, instruction);
        }
    }

    void add_counter(uint64);
    
    void add_rip(mword);
    
    void add_instruction(mword);
    
    bool cmp_to(Member_type, Pe*);
    
    void mark();
};
