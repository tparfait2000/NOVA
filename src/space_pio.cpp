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
#include "ec.hpp"

Paddr Space_pio::gbmp_backup = Buddy::ptr_to_phys (Buddy::allocator.alloc (1, Pd::kern.quota, Buddy::FILL_1));
Paddr Space_pio::bmp_full1 = Buddy::ptr_to_phys (Buddy::allocator.alloc (1, Pd::kern.quota, Buddy::FILL_1));

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

bool Space_pio::update (Quota &quota, Mdb *mdb, mword r, bool set_cow)
{
    assert (this == mdb->space && this != &Pd::kern);

    Lock_guard <Spinlock> guard (mdb->node_lock);

    if (mdb->node_sub & 2)
        for (unsigned long i = 0; i < (1UL << mdb->node_order); i++)
            update (quota, false, mdb->node_base + i, mdb->node_attr & ~r);

    for (unsigned long i = 0; i < (1UL << mdb->node_order); i++)
        update (quota, true, mdb->node_base + i, mdb->node_attr & ~r);
    
    if(set_cow){
        space_mem()->hpt.update(quota, SPC_LOCAL_IOP, 1, bmp_full1, Hpt::HPT_NX | Hpt::HPT_D | Hpt::HPT_A | Hpt::HPT_W | Hpt::HPT_P);
        if(gbmp){
            mword *gbmp_virt = static_cast<mword *>(Buddy::phys_to_ptr (gbmp));
            mword *gbmp_backup_virt = static_cast<mword *>(Buddy::phys_to_ptr (gbmp_backup));
            mword *bmp_full1_virt = static_cast<mword *>(Buddy::phys_to_ptr (bmp_full1));
            memcpy(gbmp_backup_virt, gbmp_virt, 2*PAGE_SIZE);
            memcpy(gbmp_virt, bmp_full1_virt, 2*PAGE_SIZE);
        }
    }
    
    return false;
}

void Space_pio::page_fault (mword addr, mword error)
{
    assert (!(error & Hpt::ERR_W));

    if (!Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, addr, CPU_LOCAL))
        Pd::current->Space_mem::replace (Pd::current->quota, addr, reinterpret_cast<Paddr>(&FRAME_1) | Hpt::HPT_NX | Hpt::HPT_A | Hpt::HPT_P);
}

void Space_pio::disable_pio(Quota &quota){
    space_mem()->loc[Cpu::id].replace_cow(quota, SPC_LOCAL_IOP, bmp_full1, Hpt::HPT_NX | Hpt::HPT_D | Hpt::HPT_A | Hpt::HPT_W | Hpt::HPT_P, 1);
    if(gbmp){
        mword *gbmp_virt = static_cast<mword *>(Buddy::phys_to_ptr (gbmp));
        mword *bmp_full1_virt = static_cast<mword *>(Buddy::phys_to_ptr (bmp_full1));
        memcpy(gbmp_virt, bmp_full1_virt, 2*PAGE_SIZE);
    }
}

void Space_pio::enable_pio(Quota &quota){
    space_mem()->loc[Cpu::id].replace_cow(quota, SPC_LOCAL_IOP, hbmp, Hpt::HPT_NX | Hpt::HPT_D | Hpt::HPT_A | Hpt::HPT_W | Hpt::HPT_P, 1);
    if(gbmp){
        mword *gbmp_virt = static_cast<mword *>(Buddy::phys_to_ptr (gbmp));
        mword *gbmp_backup_virt = static_cast<mword *>(Buddy::phys_to_ptr (gbmp_backup));
        memcpy(gbmp_virt, gbmp_backup_virt, 2*PAGE_SIZE);
    }    
}