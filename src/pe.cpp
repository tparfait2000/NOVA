/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.cpp
 * Author: parfait
 * 
 * Created on 3 octobre 2018, 14:34
 */

#include "pe.hpp"
#include "pd.hpp"
#include "string.hpp"
Slab_cache Pe::cache(sizeof (Pe), 32);
size_t Pe::number = 0;
Queue<Pe> Pe::pe_states;
unsigned Pe::ipi[2][NUM_IPI];
unsigned Pe::msi[2][NUM_MSI];
unsigned Pe::lvt[2][NUM_LVT];
unsigned Pe::gsi[2][NUM_GSI];
unsigned Pe::exc[2][NUM_EXC];
unsigned Pe::vmi[2][NUM_VMI];
unsigned Pe::vtlb_gpf[2];
unsigned Pe::vtlb_hpf[2];
unsigned Pe::vtlb_fill[2];
unsigned Pe::vtlb_flush[2];
unsigned Pe::rep_io[2];
unsigned Pe::simple_io[2];
unsigned Pe::io[2];
unsigned Pe::pmi_ss[2];
unsigned Pe::pio[2];
unsigned Pe::mmio[2];
unsigned Pe::rep_prefix[2];
unsigned Pe::hlt_instr[2];
uint64 Pe::nb_pe;

Pe::Pe(const char* ec_name, const char* pd_name, mword rip_value) : rip(rip_value), prev(nullptr), next(nullptr){
    copy_string(ec, ec_name);
    copy_string(pd, pd_name);  
    numero = number;
    number++;
};

Pe::~Pe() {
    number--;
}

void Pe::add_counter(uint64 counter){
    retirement_counter = counter;
}

void Pe::add_rip(mword rip_value){
    rip = rip_value;
}

void Pe::add_instruction(mword instruction_value){
    instruction = instruction_value;
}

bool Pe::cmp_to(Member_type member, Pe* pe){
    switch (member){
        case RETIREMENT_COUNTER:
            return retirement_counter == pe->retirement_counter;
        case REGISTER_RIP:
            return rip == pe->rip;
        default:
            Console::panic("Unknown Member_type");
    }
}

void Pe::mark(){
    marked = true;
}
void Pe::add_pe_state(Pe* pe){
    pe_states.enqueue(pe);
}

void Pe::add_pe_state(const char* ec_name, const char* pd_name, mword rip_value, mword attrib){
    Pe* pe = new (Pd::kern.quota) Pe(ec_name, pd_name, rip_value);
    pe->attr = attrib;
    pe_states.enqueue(pe);
}

void Pe::free_recorded_pe() {
    Pe *pe = nullptr;
    while (pe_states.dequeue(pe = pe_states.head())) {
        Pe::destroy(pe, Pd::kern.quota);
    }
}

void Pe::dump(bool all){
    Pe *pe = pe_states.tail();
    if(!pe)
        return;
    do {
        if(all || pe->is_marked())
            pe->print();
        pe = pe->get_previous();
    } while(pe != pe_states.tail());
}

void Pe::reset_counter(){
    for(unsigned i=0 ; i < 2; i++) {
        vtlb_gpf[i] = vtlb_hpf[i] = vtlb_fill[i] = vtlb_flush[i] = rep_io[i] = simple_io[i] = io[i] = pmi_ss[i] = pio[i] = mmio[i] = rep_prefix[i] = hlt_instr[i] = 0;
        for (unsigned j = 0; j < NUM_IPI; j++)
            ipi[i][j] = 0;
        for (unsigned j = 0; j < NUM_MSI; j++)
            msi[i][j] = 0;
        for (unsigned j = 0; j < NUM_LVT; j++)
            lvt[i][j] = 0;
        for (unsigned j = 0; j < NUM_GSI; j++)
            gsi[i][j] = 0;
        for (unsigned j = 0; j < NUM_EXC; j++)
            exc[i][j] = 0;
        for (unsigned j = 0; j < NUM_VMI; j++)
            vmi[i][j] = 0;
    }
}

void Pe::counter(char* str){
    char s[20];
    *str = '\0';
    unsigned n = 0;
    for (unsigned j = 0; j < NUM_IPI; j++)
        if(ipi[0][j] || ipi[1][j]) {
            n = Console::sprint(s, "IPI%u %u %u ", j, ipi[0][j], ipi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_MSI; j++)
        if(msi[0][j] || msi[1][j]) {
            n = Console::sprint(s, "MSI%u %u %u ", j, msi[0][j], msi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_LVT; j++)
        if(lvt[0][j] || lvt[1][j]) {
            n = Console::sprint(s, "lvt%u %u %u ", j,  lvt[0][j], lvt[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_GSI; j++)
        if(gsi[0][j] || gsi[1][j]) {
            n = Console::sprint(s, "gsi%u %u %u ", j, gsi[0][j], gsi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_EXC; j++)
        if(exc[0][j] || exc[1][j]) {
            n = Console::sprint(s, "exc%u %u %u ", j, exc[0][j], exc[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_VMI; j++)
        if(vmi[0][j] || vmi[1][j]) {
            n = Console::sprint(s, "vmi%u %u %u ", j, vmi[0][j], vmi[0][j]);
            strcat(str, s, n);
        }
}
