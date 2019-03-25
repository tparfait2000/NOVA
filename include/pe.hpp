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
    static Queue<Pe> pe_states;
    
    static size_t number;
    char ec[MAX_STR_LENGTH];
    char pd[MAX_STR_LENGTH];
    mword rip;
    Pe* prev;
    Pe* next;
    size_t numero = 0;
    bool marked = false;
    uint64 retirement_counter = 0;
    mword instruction = 0;
    mword attr = 0; 
    
public:
    /**
     These static variables are for statistics
     */
    static unsigned ipi[2][NUM_IPI];
    static unsigned msi[2][NUM_MSI];
    static unsigned lvt[2][NUM_LVT];
    static unsigned gsi[2][NUM_GSI];
    static unsigned exc[2][NUM_EXC];
    static unsigned vmi[2][NUM_VMI];
    static unsigned vtlb_gpf[2];
    static unsigned vtlb_hpf[2];
    static unsigned vtlb_fill[2];
    static unsigned vtlb_flush[2];
    static unsigned rep_io[2];
    static unsigned simple_io[2];
    static unsigned io[2];
    static unsigned pmi_ss[2];
    static unsigned pio[2];
    static unsigned mmio[2];
    static unsigned rep_prefix[2];
    static unsigned hlt_instr[2];
    static uint64 nb_pe;
    //----------------------------------------------
        
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
        RETIREMENT_COUNTER  = 0,
        REGISTER_RIP        = 1,
    };
    
    enum {
        RUN_NUMBER_1        = 1UL << 0,
        RET_STATE_SYS       = 1UL << 1,
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
    
    Pe* get_previous(){
        return prev;
    };
    
    void print(){
//        char num_to_str[20];
//        if(retirement_counter < MAX_INSTRUCTION)
//            Console::sprint(num_to_str, "%llu", retirement_counter);
//        else
//            Console::sprint(num_to_str, "%llx", retirement_counter);
//        Console::print("Pe_state %s %s %lu %lx %s %lx", ec, pd, numero, rip, num_to_str, instruction);
        Console::print("%s %s %lx %lx", ec, pd, rip, attr);
    }

    void add_counter(uint64);
    
    void add_rip(mword);
    
    void add_instruction(mword);
    
    bool cmp_to(Member_type, Pe*);
    
    void mark();
    
    bool is_marked() { return marked; }
    
    static size_t get_number(){
        return number;
    }
    
    static void add_pe_state(const char*, const char*, mword, mword = 0);
    
    static void add_pe_state(Pe*);
    
    static void free_recorded_pe();
    
    static void dump(bool = false);
    
    static void reset_counter();
    
    static void counter(char*);
    
};
