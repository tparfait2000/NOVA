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
#include "string.hpp"
Slab_cache Pe::cache(sizeof (Pe), 32);
size_t Pe::number = 0;
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