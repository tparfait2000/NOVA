/*
 * Memory Space
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
#include "hazards.hpp"
#include "hip.hpp"
#include "lapic.hpp"
#include "mtrr.hpp"
#include "pd.hpp"
#include "stdio.hpp"
#include "svm.hpp"
#include "vectors.hpp"

unsigned Space_mem::did_ctr;

void Space_mem::init (unsigned cpu)
{
    if (cpus.set (cpu)) {
        loc[cpu].sync_from (Pd::kern.loc[cpu], CPU_LOCAL, SPC_LOCAL);
        loc[cpu].sync_master_range (LINK_ADDR, CPU_LOCAL);
    }
}

bool Space_mem::update (Mdb *mdb, mword r)
{
    assert (this == mdb->space && this != &Pd::kern);

    Lock_guard <Spinlock> guard (mdb->node_lock);

    Paddr p = mdb->node_phys << PAGE_BITS;
    mword b = mdb->node_base << PAGE_BITS;
    mword o = mdb->node_order;
    mword a = mdb->node_attr & ~r;
    mword s = mdb->node_sub;

    if (s & 1 && Dpt::ord != ~0UL) {
        mword ord = min (o, Dpt::ord);
        for (unsigned long i = 0; i < 1UL << (o - ord); i++)
            dpt.update (b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (Dpt::ord + PAGE_BITS)), a, r ? Dpt::TYPE_DN : Dpt::TYPE_UP);
    }

    if (s & 2) {
        if (Vmcb::has_npt()) {
            mword ord = min (o, Hpt::ord);
            for (unsigned long i = 0; i < 1UL << (o - ord); i++)
                npt.update (b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), r ? Hpt::TYPE_DN : Hpt::TYPE_UP);
        } else {
            mword ord = min (o, Ept::ord);
            for (unsigned long i = 0; i < 1UL << (o - ord); i++)
                ept.update (b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Ept::hw_attr (a, mdb->node_type), r ? Ept::TYPE_DN : Ept::TYPE_UP);
        }
        if (r)
            gtlb.merge (cpus);
    }

    if (s & 4) {
        if (a)
            a |= Hpt::HPT_PWT;
    }


    if ((mdb->node_base >= USER_ADDR >> PAGE_BITS) ||
        (mdb->node_base + (1UL << o) > USER_ADDR >> PAGE_BITS) ||
        (mdb->node_base + (1UL << o) <= mdb->node_base))
        return false;

    mword ord = min (o, Hpt::ord);
    bool f = false;

    for (unsigned long i = 0; i < 1UL << (o - ord); i++)
        f |= hpt.update (b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), r ? Hpt::TYPE_DN : Hpt::TYPE_UP);

    if (r || f) {

        for (unsigned j = 0; j < sizeof (loc) / sizeof (*loc); j++) {
            if (!loc[j].addr())
                continue;

            for (unsigned long i = 0; i < 1UL << (o - ord); i++)
                loc[j].update (b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), Hpt::TYPE_DF);
        }

        htlb.merge (cpus);
    }

    return (r || f);
}

void Space_mem::shootdown()
{
    for (unsigned cpu = 0; cpu < NUM_CPU; cpu++) {

        if (!Hip::cpu_online (cpu))
            continue;

        Pd *pd = Pd::remote (cpu);

        if (!pd->htlb.chk (cpu) && !pd->gtlb.chk (cpu))
            continue;

        if (Cpu::id == cpu) {
            Cpu::hazard |= HZD_SCHED;
            continue;
        }

        unsigned ctr = Counter::remote (cpu, 1);

        Lapic::send_ipi (cpu, VEC_IPI_RKE);

        if (!Cpu::preemption)
            asm volatile ("sti" : : : "memory");

        while (Counter::remote (cpu, 1) == ctr)
            pause();

        if (!Cpu::preemption)
            asm volatile ("cli" : : : "memory");
    }
}

void Space_mem::insert_root (uint64 s, uint64 e, mword a)
{
    for (uint64 p = s; p < e; s = p) {

        unsigned t = Mtrr::memtype (s, p);

        for (uint64 n; p < e; p = n)
            if (Mtrr::memtype (p, n) != t)
                break;

        if (s > ~0UL)
            break;

        if ((p = min (p, e)) > ~0UL)
            p = static_cast<uint64>(~0UL) + 1;

        addreg (static_cast<mword>(s >> PAGE_BITS), static_cast<mword>(p - s) >> PAGE_BITS, a, t);
    }
}

bool Space_mem::insert_utcb (mword b, mword phys)
{
    if (!b)
        return true;

    Mdb *mdb = new Mdb (this, phys, b >> PAGE_BITS, 0, 0x3);

    if (tree_insert (mdb))
        return true;

    delete mdb;

    return false;
}

bool Space_mem::remove_utcb (mword b)
{
    if (!b)
        return false;

    Mdb *mdb = tree_lookup(b >> PAGE_BITS, false);
    if (!mdb)
        return false;

    mdb->demote_node(0x3);

    if (mdb->remove_node() && tree_remove(mdb)) {
        Rcu::call (mdb);
        return true;
    }

    return false;
}
