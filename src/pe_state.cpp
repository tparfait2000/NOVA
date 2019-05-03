/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe_state.cpp
 * Author: parfait
 * 
 * Created on 3 octobre 2018, 14:34
 */

#include "pe_state.hpp"
#include "pd.hpp"
#include "string.hpp"
#include "regs.hpp"
#include "vmx.hpp"
Slab_cache Pe_state::cache(sizeof (Pe_state), 32);
size_t Pe_state::number = 0;
Queue<Pe_state> Pe_state::pe_state;

Pe_state::Pe_state(Exc_regs* r, uint64 inst_count, uint8 run_number, mword int_number) : 
    retirement_counter(inst_count), run_no(run_number), int_no(int_number), prev(nullptr), next(nullptr) {
    rax = r->REG(ax);
    rbx = r->REG(bx);
    rcx = r->REG(cx);
    rdx = r->REG(dx);
    rsi = r->REG(si);
    rdi = r->REG(di);
    rbp = r->REG(bp);
    rsp = r->REG(sp);
    rip = r->REG(ip);
    r8  = r->r8;
    r9  = r->r9;
    r10 = r->r10;
    r11 = r->r11;
    r12 = r->r12;
    r13 = r->r13;
    r14 = r->r14;
    r15 = r->r15;
    numero = number;
    number++;
};

Pe_state::Pe_state(Cpu_regs* cpu_regs, uint64 inst_count, uint8 run_number, mword int_number) : 
    retirement_counter(inst_count), run_no(run_number), int_no(int_number), prev(nullptr), next(nullptr) {
    rax = cpu_regs->REG(ax);
    rbx = cpu_regs->REG(bx);
    rcx = cpu_regs->REG(cx);
    rdx = cpu_regs->REG(dx);
    rsi = cpu_regs->REG(si);
    rdi = cpu_regs->REG(di);
    rbp = cpu_regs->REG(bp);
    rsp = Vmcs::read(Vmcs::GUEST_RSP);
    rip = Vmcs::read(Vmcs::GUEST_RIP);
    r8  = cpu_regs->r8;
    r9  = cpu_regs->r9;
    r10 = cpu_regs->r10;
    r11 = cpu_regs->r11;
    r12 = cpu_regs->r12;
    r13 = cpu_regs->r13;
    r14 = cpu_regs->r14;
    r15 = cpu_regs->r15;
    numero = number;
    number++;
};

Pe_state::~Pe_state() {
    number--;
}

void Pe_state::add_pe_state(Pe_state* pes){
    pe_state.enqueue(pes);
}

void Pe_state::set_current_pe_sub_reason(mword sub_reason) {
    Pe_state *p = pe_state.tail();
    if(p)
        p->sub_reason = sub_reason;
}

void Pe_state::set_current_pe_diff_reason(mword reason){
    Pe_state *p = pe_state.tail();
    if(p)
        pe_state.tail()->diff_reason = reason;    
}

void Pe_state::free_recorded_pe_state() {
    Pe_state *pes = nullptr;
    while (pe_state.dequeue(pes = pe_state.head())) {
        Pe_state::destroy(pes, Pd::kern.quota);
    }
}

void Pe_state::dump(){    
    Pe_state *p = pe_state.head(), *head = pe_state.head(), *n = nullptr;
    Console::print("RUN     RAX             RBX         RCX         RDX         RSI         RDI         RBP     "
            "       RSP         RIP         R8          R9          R10         R11         R12         R13         R14         R15         Conter");
    while(p) {
        p->print();
        n = p->next;
        p = (p == n || n == head) ? nullptr : n;
    }
}