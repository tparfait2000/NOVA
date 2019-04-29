/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe_state.hpp
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
#include "regs.hpp"

class Pe_state {
    friend class Queue<Pe_state>;
    static Slab_cache cache;    
    static Queue<Pe_state> pe_state;
    
    static size_t number;
    mword rax = 0, rbx = 0, rcx = 0, rdx = 0, rbp = 0, rdi = 0, rsi = 0, rsp = 0, rip = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    mword rsp_content = 0, rip_content = 0;
    uint64 retirement_counter = 0;
    uint8 run_no; 
    mword int_no;
    Pe_state* prev;
    Pe_state* next;
    size_t numero = 0;
    mword instruction = 0;
    mword attr = 0; 
    mword sub_reason = 0;
    int diff_reason = 0;
    
public:
    
    /**
     * 
     * @param ec
     * @param pd
     * @param rip_value
     * @param counter
     */
    Pe_state(Exc_regs*, uint64, uint8, mword); 
    Pe_state(Cpu_regs*, uint64, uint8, mword); 
    Pe_state &operator = (Pe_state const &);
    
    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

    ALWAYS_INLINE
    static inline void destroy (Pe_state *obj, Quota &quota) { obj->~Pe_state(); cache.free (obj, quota); }
    
    Pe_state(const Pe_state& orig);    
    ~Pe_state();
    
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pe_state* pe_state = static_cast<Pe_state*> (ptr);
        pe_state->~Pe_state();
        cache.free (ptr, quota);
    }
    
    Pe_state* get_next(){
        return next;
    };
    
    Pe_state* get_previous(){
        return prev;
    };
    
    void print(){
        Console::print("%d, %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %#8lx %ld"
        "%#8lx %#8lx %#8lx, %#12llx, %ld:%ld %d", run_no, rax, rbx, rcx, rdx, rbp, rdi, rsi, rsp, rip, r8, r9, 
                r10, r11, r12, r13, r14, r15, retirement_counter, int_no, sub_reason, diff_reason);
    }

    static size_t get_number(){
        return number;
    }
    
    static void add_pe_state(Pe_state*);
    
    static void set_current_pe_sub_reason(mword);
    
    static void set_current_pe_diff_reason(int);
    
    static void free_recorded_pe_state();
    
    static void dump();
};
