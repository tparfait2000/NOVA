/*
 * Event Counters
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
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

#include "counter.hpp"
#include "stdio.hpp"
#include "x86.hpp"

unsigned    Counter::ipi[NUM_IPI];
unsigned    Counter::lvt[NUM_LVT];
unsigned    Counter::gsi[NUM_GSI];
unsigned    Counter::exc[NUM_EXC];
unsigned    Counter::vmi[NUM_VMI];
unsigned    Counter::vtlb_gpf;
unsigned    Counter::vtlb_hpf;
unsigned    Counter::vtlb_fill;
unsigned    Counter::vtlb_flush;
unsigned    Counter::schedule;
unsigned    Counter::helping;
unsigned    Counter::rep_io;
unsigned    Counter::simple_io;
unsigned    Counter::io;
unsigned    Counter::pmi_ss;
unsigned    Counter::nb_pe;
unsigned    Counter::pio;
unsigned    Counter::mmio;
uint64      Counter::cycles_idle;

void Counter::dump()
{
    trace (0, "TIME: %16llu", rdtsc());
    trace (0, "IDLE: %16llu", Counter::cycles_idle);
    trace (0, "VGPF: %16u", Counter::vtlb_gpf);
    trace (0, "VHPF: %16u", Counter::vtlb_hpf);
    trace (0, "VFIL: %16u", Counter::vtlb_fill);
    trace (0, "VFLU: %16u", Counter::vtlb_flush);
    trace (0, "SCHD: %16u", Counter::schedule);
    trace (0, "HELP: %16u", Counter::helping);
    trace (0, "REP_IO: %14u", Counter::rep_io);
    trace (0, "SIMPLE_IO: %11u", Counter::simple_io);
    trace (0, "PIO: %17u", Counter::pio);
    trace (0, "MMIO: %16u", Counter::mmio);
    trace (0, "T_IO: %16u", Counter::io);
    trace (0, "PMI_SS: %14u", Counter::pmi_ss);
    trace (0, "NB_PE: %15u", Counter::nb_pe);
    
    Counter::vtlb_gpf = Counter::vtlb_hpf = Counter::vtlb_fill = Counter::vtlb_flush = Counter::schedule = Counter::helping = Counter::rep_io = 
    Counter::io = Counter::simple_io = Counter::pmi_ss = Counter::nb_pe = Counter::pio = Counter::mmio = 0;

    for (unsigned i = 0; i < sizeof (Counter::ipi) / sizeof (*Counter::ipi); i++)
        if (Counter::ipi[i]) {
            trace (0, "IPI %#4x: %12u", i, Counter::ipi[i]);
            Counter::ipi[i] = 0;
        }

    for (unsigned i = 0; i < sizeof (Counter::lvt) / sizeof (*Counter::lvt); i++)
        if (Counter::lvt[i]) {
            trace (0, "LVT %#4x: %12u", i, Counter::lvt[i]);
            Counter::lvt[i] = 0;
        }

    for (unsigned i = 0; i < sizeof (Counter::gsi) / sizeof (*Counter::gsi); i++)
        if (Counter::gsi[i]) {
            trace (0, "GSI %#4x: %12u", i, Counter::gsi[i]);
            Counter::gsi[i] = 0;
        }

    for (unsigned i = 0; i < sizeof (Counter::exc) / sizeof (*Counter::exc); i++)
        if (Counter::exc[i]) {
            trace (0, "EXC %#4x: %12u", i, Counter::exc[i]);
            Counter::exc[i] = 0;
        }

    for (unsigned i = 0; i < sizeof (Counter::vmi) / sizeof (*Counter::vmi); i++)
        if (Counter::vmi[i]) {
            trace (0, "VMI %#4x: %12u", i, Counter::vmi[i]);
            Counter::vmi[i] = 0;
        }
}
