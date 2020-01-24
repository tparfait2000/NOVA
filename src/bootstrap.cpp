/*
 * Bootstrap Code
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2015 Alexander Boettcher, Genode Labs GmbH
 *
 * This file is part of the NOVA microhypervisor.
 *
 * NOVA is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * NOVA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License version 2 for more details.
 */

#include "compiler.hpp"
#include "ec.hpp"
#include "hip.hpp"
#include "msr.hpp"
#include "lapic.hpp"

extern "C" NORETURN
void bootstrap()
{
//    static mword barrier;

    Cpu::init();

    // Create idle EC
    Ec::current = new (Pd::root) Ec (Pd::current = &Pd::kern, Ec::idle, Cpu::id, "idle_ec");
    Ec::current->add_ref();
    Pd::current->add_ref();
    Space_obj::insert_root (Pd::kern.quota, Sc::current = new (Pd::root) Sc (&Pd::kern, Cpu::id, Ec::current));
    Sc::current->add_ref();

//  Barrier: wait for all ECs to arrive here
//  for (Atomic::add (barrier, 1UL); barrier != Cpu::online; pause()) ;

    Msr::write<uint64>(Msr::IA32_TSC, 0);

    // Create root task
    if (Cpu::bsp) {
        Hip::add_check();
        Ec *root_ec = new (Pd::root) Ec (&Pd::root, NUM_EXC + 1, &Pd::root, Ec::root_invoke, Cpu::id, 0, USER_ADDR - 2 * PAGE_SIZE, 0, nullptr, "root_ec");
        Sc *root_sc = new (Pd::root) Sc (&Pd::root, NUM_EXC + 2, root_ec, Cpu::id, Sc::default_prio, Sc::default_quantum);
        root_sc->remote_enqueue();
    }

    Hip::list_memory();
    Lapic::activate_pmi();
//    Logstore::log_on = true;
//    Console::print_on = true;
    Sc::schedule();
}
