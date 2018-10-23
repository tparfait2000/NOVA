/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pending_int.cpp
 * Author: parfait
 * 
 * Created on 5 octobre 2018, 13:26
 */

#include "pending_int.hpp"
#include "pd.hpp"
#include "gsi.hpp"
#include "lapic.hpp"

Slab_cache Pending_int::cache(sizeof (Pending_int), 32);
Queue<Pending_int> Pending_int::pendings;
size_t Pending_int::number = 0;

Pending_int::Pending_int(Int_type t, unsigned v): type(t), vector(v), prev(nullptr), next(nullptr) {
    number++;
}

Pending_int::~Pending_int() {
    number--;
}

void Pending_int::add_pending_interrupt(Int_type t, unsigned v){
    pendings.enqueue(new (Pd::kern.quota) Pending_int(t, v));
}

void Pending_int::free_recorded_interrupt() {
    Pending_int *pi = nullptr;
    while (pendings.dequeue(pi = pendings.head())) {
        Pending_int::destroy(pi, Pd::kern.quota);
    }
}

void Pending_int::exec_pending_interrupt(){
    Pending_int *pi = nullptr;
    while (pendings.dequeue(pi = pendings.head())) {
        switch(pi->type){
            case INT_GSI:
                Gsi::exec_gsi(pi->vector, true);
                break;
            case INT_LAPIC:
                Lapic::exec_lvt(pi->vector, true);
                break;
            case INT_MSI:
                Dmar::exec_msi(pi->vector, true);
                break;
            default:
                Console::panic("Unhandled pending interrupt");
        }
        destroy(pi, Pd::kern.quota);
    }
}

size_t Pending_int::get_numero(){
    return number;
}