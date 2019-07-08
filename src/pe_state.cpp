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
#include "ec.hpp"
#include "lapic.hpp"

Slab_cache Pe_state::cache(sizeof (Pe_state), 32);
size_t Pe_state::number = 0;
Queue<Pe_state> Pe_state::pe_states, Pe_state::log_pe_states;

Pe_state::Pe_state(Exc_regs* r, uint64 inst_count, uint8 run, mword int_number, bool vcpu) : 
    retirement_counter(inst_count), run_number(run), interrupt_number(int_number), is_vcpu(vcpu), prev(nullptr), next(nullptr) {
    rax = r->REG(ax);
    rbx = r->REG(bx);
    rcx = r->REG(cx);
    rdx = r->REG(dx);
    rsi = r->REG(si);
    rdi = r->REG(di);
    rbp = r->REG(bp);
    if(is_vcpu){
        rsp = Vmcs::read(Vmcs::GUEST_RSP);
        rip = Vmcs::read(Vmcs::GUEST_RIP);
    } else {
        rsp = r->REG(sp);
        rip = r->REG(ip);
    }
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

Pe_state::Pe_state(const Pe_state& orig) : retirement_counter(orig.retirement_counter), 
        run_number(orig.run_number), interrupt_number(orig.interrupt_number), is_vcpu(orig.is_vcpu), prev(nullptr), next(nullptr){
    rax = orig.rax;
    rbx = orig.rbx;
    rcx = orig.rcx;
    rdx = orig.rdx;
    rsi = orig.rsi;
    rdi = orig.rdi;
    rbp = orig.rbp;
    rsp = orig.rsp;
    rip = orig.rip;
    r8  = orig.r8;
    r9  = orig.r9;
    r10 = orig.r10;
    r11 = orig.r11;
    r12 = orig.r12;
    r13 = orig.r13;
    r14 = orig.r14;
    r15 = orig.r15;
    numero = number;
    number++;
}

Pe_state::Pe_state(size_t c, size_t mm, mword pa, Paddr p0, Paddr p1, Paddr p2, mword pta, mword pti) : 
    count(c), page_twin_index(pti), missmatch_addr(mm), page_addr(pa), page_twin_addr(pta), 
        phys0(p0), phys1(p1), phys2(p2), prev(nullptr), next(nullptr){
    type = PE_STATE_RESOLVE_COWFAULT;
    numero = number;
    number++;
}

Pe_state::Pe_state(mword addr, Paddr p0, Paddr p1, Paddr p2, mword ptap) : page_addr_placed(addr), 
        page_twin_addr_placed(ptap), phys0_placed(p0), phys1_placed(p1), phys2_placed(p2),
        prev(nullptr), next(nullptr){
    type = PE_STATE_PLACE_PHYS0;    
    numero = number;
    number++;
}

Pe_state::Pe_state(mword int_rip, uint8 run, mword int_number, uint64 inst_count) : 
        m_rip(int_rip), retirement_counter(inst_count), run_number(run), 
        interrupt_number(int_number), prev(nullptr), next(nullptr){
    type = PE_STATE_INTERRUPT;    
    numero = number;
    number++;
}

Pe_state::Pe_state(mword eip, mword esp, mword eflag, mword reason, uint8 run, uint64 inst_count) : 
        m_rip(eip), m_rsp(esp), m_eflag(eflag), retirement_counter(inst_count), 
        run_number(run), interrupt_number(reason), prev(nullptr), next(nullptr){
    type = PE_STATE_VM_EXIT;    
    numero = number;
    number++;
}

Pe_state::Pe_state(mword v, Paddr p0, Paddr p1, Paddr p2, mword eip, mword v1, 
        mword v2) : m_rip(eip), page_addr(v), val1(v1), val2(v2), phys0(p0), phys1(p1), phys2(p2), 
        prev(nullptr), next(nullptr){
    type = PE_STATE_CMP;    
    numero = number;
    retirement_counter = Lapic::read_instCounter();
    number++;
}

Pe_state::~Pe_state() {
    number--;
}

void Pe_state::add_pe_state(mword v, Paddr p0, Paddr p1, Paddr p2, mword eip, mword v1, 
        mword v2){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;   
    if(number > 100000) {
        free_recorded_pe_state();
    }
    pe_states.enqueue(new (Pd::kern.quota) Pe_state(v, p0, p1, p2, eip, v1, v2));
//    Pe_state *newPe_state = new(Pd::kern.quota)Pe_state(*pes);
//    log_pe_states.enqueue(newPe_state);
}

void Pe_state::set_current_pe_sub_reason(mword sub_reason) {
    Pe_state *p = pe_states.tail()/*, *lp = log_pe_states.tail()*/;
    
    if(p)
        p->val2 = sub_reason;
//    if(lp)
//        lp->sub_reason = sub_reason;
}

void Pe_state::set_current_pe_diff_reason(mword reason){
    Pe_state *p = pe_states.tail()/*, *lp = log_pe_states.tail()*/;
    if(p)
        pe_states.tail()->val1 = reason;    
//    if(lp)
//        log_pe_states.tail()->diff_reason = reason;    
}

void Pe_state::free_recorded_pe_state() {
    Pe_state *pes = nullptr;
    while (pe_states.dequeue(pes = pe_states.head())) {
        Pe_state::destroy(pes, Pd::kern.quota);
    }
}

void Pe_state::free_recorded_log_pe_state() {
    Pe_state *lpes = nullptr;
    while (log_pe_states.dequeue(lpes = log_pe_states.head())) {
        Pe_state::destroy(lpes, Pd::kern.quota);
    }
}

void Pe_state::dump(bool from_head, uint32 nb){    
    if(!pe_states.head())
        return;
    Pe_state *p = from_head ? pe_states.head() : pe_states.tail(), *end = from_head ?
        pe_states.head() : pe_states.tail(), *n = nullptr;
    Console::print("RUN     RAX             RBX         RCX         RDX         RSI         RDI         RBP     "
            "       RSP         RIP         R8          R9          R10         R11         R12         R13         R14         R15         Conter");
    if(nb){
        while(p && nb) {
            p->print();
            n = from_head ? p->next : p->prev;
            p = (p == n || n == end) ? nullptr : n;
            nb--;
        }
    } else {
        while(p) {
            p->print();
            n = from_head ? p->next : p->prev;
            p = (p == n || n == end) ? nullptr : n;
        }
    }
}

void Pe_state::dump_log(){    
    Pe_state *p = log_pe_states.head(), *head = log_pe_states.head(), *n = nullptr;
    Console::print("RUN     RAX             RBX         RCX         RDX         RSI         RDI         RBP     "
            "       RSP         RIP         R8          R9          R10         R11         R12         R13         R14         R15         Conter");
    while(p) {
        p->print();
        n = p->next;
        p = (p == n || n == head) ? nullptr : n;
    }
}

void Pe_state::print(){
//        trace(0, "%d, A %010lx B %010lx C %010lx D %010lx S %010lx D %010lx B %010lx S %010lx I %010lx R8 %010lx %010lx %010lx %010lx %010lx "
//        "%010lx %010lx %010lx, %0#12llx, %ld:%ld %lx", run_no, rax, rbx, rcx, rdx, rbp, rdi, rsi, rsp, rip, r8, r9, 
//                r10, r11, r12, r13, r14, r15, retirement_counter, int_no, sub_reason, diff_reason);
        switch(type){
            case PE_STATE_RESOLVE_COWFAULT:
                trace(0, "  count %lu MM %lx c %lx %lx %lx %lx ce %lx  index %lu", count, missmatch_addr, 
                    page_addr, phys0, phys1, phys2, page_twin_addr, page_twin_index);
                break;
            case PE_STATE_PLACE_PHYS0:
                trace(0, "  Placing c %lx %lx %lx %lx ce %lx", page_addr_placed, phys0_placed, 
                        phys1_placed, phys2_placed, page_twin_addr_placed);
                break;
            case PE_STATE_INTERRUPT:
                trace(0, "  Interupt rip %lx run %u vec %lu counter %llx", m_rip, run_number, 
                        interrupt_number, retirement_counter);
                break;
            case PE_STATE_VM_EXIT:
                trace(0, "  VM Exit reason rip %lx esp %lx eflag %lx reason %lx run %u counter %llx", 
                        m_rip, m_rsp, m_eflag, interrupt_number, run_number, retirement_counter);
                break;
            case PE_STATE_CMP:
                trace(0, "  Compare v %lx p0 %lx p1 %lx p2 %lx rip %lx val1 %lx val2 %lx counter %llx", 
                        page_addr, phys0, phys1, phys2, m_rip, val1, val2, retirement_counter);
                break;
            case PE_STATE_DEFAULT:
                break;
        }
    }