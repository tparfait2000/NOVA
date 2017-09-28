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
uint64      Counter::cycles_idle;
mword       Counter::ip_in;
mword       Counter::ip_out;

void Counter::remote_dump(unsigned c)
{
    volatile mword    * ip_in    = reinterpret_cast<volatile mword    *>(reinterpret_cast<mword>(&Counter::ip_in) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile mword    * ip_out   = reinterpret_cast<volatile mword    *>(reinterpret_cast<mword>(&Counter::ip_out) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile uint64   * idle     = reinterpret_cast<volatile uint64   *>(reinterpret_cast<mword>(&Counter::cycles_idle) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * gpf      = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::vtlb_gpf) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * hpf      = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::vtlb_hpf) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * fill     = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::vtlb_fill) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * flush    = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::vtlb_flush) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * schedule = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::schedule) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    volatile unsigned * helping  = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(&Counter::helping) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);

    trace (0, "IP in : %16lx", *ip_in);
    trace (0, "IP out: %16lx", *ip_out);
    trace (0, "IDLE: %16llu", *idle);
    trace (0, "VGPF: %16u", *gpf);
    trace (0, "VHPF: %16u", *hpf);
    trace (0, "VFIL: %16u", *fill);
    trace (0, "VFLU: %16u", *flush);
    trace (0, "SCHD: %16u", *schedule);
    trace (0, "HELP: %16u", *helping);

    *gpf = *hpf = *fill = *flush = *schedule = *helping = 0;

    volatile unsigned * remote_ipi = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(ipi) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    for (unsigned i = 0; i < sizeof (Counter::ipi) / sizeof (*Counter::ipi); i++)
        if (remote_ipi[i]) {
            trace (0, "IPI %#4x: %12u", i, remote_ipi[i]);
        }

    volatile unsigned * remote_lvt = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(lvt) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    for (unsigned i = 0; i < sizeof (Counter::lvt) / sizeof (*Counter::lvt); i++)
        if (remote_lvt[i]) {
            trace (0, "LVT %#4x: %12u", i, remote_lvt[i]);
        }

    volatile unsigned * remote_gsi = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(gsi) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    for (unsigned i = 0; i < sizeof (Counter::gsi) / sizeof (*Counter::gsi); i++)
        if (remote_gsi[i]) {
            trace (0, "GSI %#4x: %12u", i, remote_gsi[i]);
        }

    volatile unsigned * remote_exc = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(exc) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    for (unsigned i = 0; i < sizeof (Counter::exc) / sizeof (*Counter::exc); i++)
        if (remote_exc[i]) {
            trace (0, "EXC %#4x: %12u", i, remote_exc[i]);
        }

    volatile unsigned * remote_vmi = reinterpret_cast<volatile unsigned *>(reinterpret_cast<mword>(vmi) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    for (unsigned i = 0; i < sizeof (Counter::vmi) / sizeof (*Counter::vmi); i++)
        if (remote_vmi[i]) {
            trace (0, "VMI %#4x: %12u", i, remote_vmi[i]);
        }
}

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

    Counter::vtlb_gpf = Counter::vtlb_hpf = Counter::vtlb_fill = Counter::vtlb_flush = Counter::schedule = Counter::helping = 0;

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
