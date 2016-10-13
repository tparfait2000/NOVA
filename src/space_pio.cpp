/*
 * Port I/O Space
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

#include "pd.hpp"
#include "tss.hpp"
#include "ec.hpp"

Space_mem *Space_pio::space_mem()
{
    return static_cast<Pd *>(this);
}

Paddr Space_pio::walk (Quota &quota, bool host, mword idx)
{
    Paddr &bmp = host ? hbmp : gbmp;

    if (!bmp) {
        bmp = Buddy::ptr_to_phys (Buddy::allocator.alloc (1, quota, Buddy::FILL_1));

        if (host)
            space_mem()->insert (quota, SPC_LOCAL_IOP, 1, Hpt::HPT_NX | Hpt::HPT_D | Hpt::HPT_A | Hpt::HPT_W | Hpt::HPT_P, bmp);
    }

    return bmp | (idx_to_virt (idx) & (2 * PAGE_SIZE - 1));
}

void Space_pio::update (Quota &quota, bool host, mword idx, mword attr)
{
    mword *m = static_cast<mword *>(Buddy::phys_to_ptr (walk (quota, host, idx)));

    if (attr)
        Atomic::clr_mask (*m, idx_to_mask (idx));
    else
        Atomic::set_mask (*m, idx_to_mask (idx));
}

bool Space_pio::update (Quota &quota, Mdb *mdb, mword r)
{
    assert (this == mdb->space && this != &Pd::kern);

    Lock_guard <Spinlock> guard (mdb->node_lock);

    if (mdb->node_sub & 2)
        for (unsigned long i = 0; i < (1UL << mdb->node_order); i++)
            update (quota, false, mdb->node_base + i, mdb->node_attr & ~r);

    for (unsigned long i = 0; i < (1UL << mdb->node_order); i++)
        update (quota, true, mdb->node_base + i, mdb->node_attr & ~r);

    #ifdef __x86_64__
    struct Cow::cow_frame* io_frame[2];
    if (!Cow::get_new_cow_frame(&io_frame[0]) || !Cow::get_new_cow_frame(&io_frame[1]))
            Ec::current->die("cow frame exhausted on io frame");
    Paddr phys1, phys2;
    mword attr1, attr2;
    Pd::current->io_remap1 = io_frame[0]->phys_addr;
    Pd::current->io_remap2 = io_frame[1]->phys_addr;
    space_mem()->hpt.lookup(SPC_LOCAL_IOP, phys1, attr1);
    space_mem()->hpt.lookup(SPC_LOCAL_IOP + PAGE_SIZE, phys2, attr2);
    space_mem()->hpt.update(quota, SPC_LOCAL_IOP, 0, io_frame[0]->phys_addr, attr1, Hpt::TYPE_DF);
    space_mem()->hpt.update(quota, SPC_LOCAL_IOP + PAGE_SIZE, 0, io_frame[1]->phys_addr, attr2, Hpt::TYPE_DF);
    space_mem()->insert(quota, LOCAL_IOP_REMAP, 0, attr1, phys1);
    space_mem()->insert(quota, LOCAL_IOP_REMAP + PAGE_SIZE, 0, attr2, phys2);
    space_mem()->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, LOCAL_IOP_REMAP, CPU_LOCAL);
    memset(reinterpret_cast<void*> (SPC_LOCAL_IOP), ~0u, 2*PAGE_SIZE);
    #endif
    return false;
}

void Space_pio::page_fault (mword addr, mword error)
{
    assert (!(error & Hpt::ERR_W));
#ifdef __i386__
//    Console::print("addr: %08lx  iobm: %04x  &Tss::run: %p", addr, Tss::run.iobm, &Tss::run);
    bool is_io_mapped = Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, addr, CPU_LOCAL);
    if(is_io_mapped){
        struct Cow::cow_frame* io_frame[2];
        if (!Cow::get_new_cow_frame(&io_frame[0]) || !Cow::get_new_cow_frame(&io_frame[1]))
            Ec::current->die("cow frame exhausted on io frame");
        Pd::current->io_remap1 = io_frame[0]->phys_addr;
        Pd::current->io_remap2 = io_frame[1]->phys_addr;
        Paddr phys1, phys2;
        mword attr1, attr2;
        Pd::current->hpt.lookup(SPC_LOCAL_IOP, phys1, attr1);
        Pd::current->hpt.lookup(SPC_LOCAL_IOP + PAGE_SIZE, phys2, attr2);
        Pd::current->hpt.update(Pd::current->quota, SPC_LOCAL_IOP, 0, io_frame[0]->phys_addr, attr1, Hpt::TYPE_DF);
        Pd::current->hpt.update(Pd::current->quota, SPC_LOCAL_IOP + PAGE_SIZE, 0, io_frame[1]->phys_addr, attr2, Hpt::TYPE_DF);
        Pd::current->Space_mem::insert(Pd::current->quota, LOCAL_IOP_REMAP, 0, attr1, phys1);
        Pd::current->Space_mem::insert(Pd::current->quota, LOCAL_IOP_REMAP + PAGE_SIZE, 0, attr2, phys2);
        Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, LOCAL_IOP_REMAP, CPU_LOCAL);
        memset(reinterpret_cast<void*> (SPC_LOCAL_IOP), ~0u, 2*PAGE_SIZE);
    }else{
        Pd::current->Space_mem::replace (Pd::current->quota, addr, reinterpret_cast<Paddr>(&FRAME_1) | Hpt::HPT_NX | Hpt::HPT_A | Hpt::HPT_P);
    }
#endif
#ifdef __x86_64__
    if (!Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, addr, CPU_LOCAL))
        Pd::current->Space_mem::replace (Pd::current->quota, addr, reinterpret_cast<Paddr>(&FRAME_1) | Hpt::HPT_NX | Hpt::HPT_A | Hpt::HPT_P);
#endif    
}
