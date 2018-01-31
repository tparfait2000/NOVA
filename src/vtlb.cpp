/*
 * Virtual Translation Lookaside Buffer (VTLB)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
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
#include "pd.hpp"
#include "regs.hpp"
#include "stdio.hpp"
#include "vtlb.hpp"
#include "ec.hpp"
#include "svm.hpp"

size_t Vtlb::gwalk(Exc_regs *regs, mword gla, mword &gpa, mword &attr, mword &error) {
    if (EXPECT_FALSE(!(regs->cr0_shadow & Cpu::CR0_PG))) {
        gpa = gla;
        return ~0UL;
    }

    bool pse = regs->cr4_shadow & (Cpu::CR4_PSE | Cpu::CR4_PAE);
    bool pge = regs->cr4_shadow & Cpu::CR4_PGE;
    bool wp = regs->cr0_shadow & Cpu::CR0_WP;

    unsigned lev = 2;

    for (uint32 e, *pte = reinterpret_cast<uint32 *> (regs->cr3_shadow & ~PAGE_MASK);; pte = reinterpret_cast<uint32 *> (e & ~PAGE_MASK)) {

        unsigned shift = --lev * 10 + PAGE_BITS;
        pte += gla >> shift & ((1UL << 10) - 1);

        if (User::peek(pte, e) != ~0UL) {
            gpa = reinterpret_cast<Paddr> (pte);
            return ~0UL;
        }

        if (EXPECT_FALSE(!(e & TLB_P)))
            return 0;

        attr &= e & PAGE_MASK;

        if (lev && (!pse || !(e & TLB_S))) {
            mark_pte(pte, e, TLB_A);
            continue;
        }

        if (EXPECT_FALSE(!wp && error == ERR_W))
            attr = (attr & ~TLB_U) | TLB_W;

        if (EXPECT_FALSE((attr & error) != error)) {
            error |= ERR_P;
            return 0;
        }

        if (!(error & ERR_W) && !(e & TLB_D))
            attr &= ~TLB_W;

        mark_pte(pte, e, static_cast<uint32> ((attr & 3) << 5));

        attr |= e & TLB_UC;

        if (EXPECT_TRUE(pge) && (e & TLB_G))
            attr |= TLB_M;

        size_t size = 1UL << shift;

        gpa = (e & ~PAGE_MASK) | (gla & (size - 1));

        return size;
    }
}

size_t Vtlb::hwalk(mword gpa, mword &hpa, mword &attr, mword &error) {
    mword ept_attr;

    size_t size = Pd::current->ept.lookup(gpa, hpa, ept_attr);

    if (size) {

        if (EXPECT_FALSE(!(ept_attr & Ept::EPT_W)))
            attr &= ~TLB_W;

        if (EXPECT_FALSE((attr & error) != error)) {
            error = (ept_attr & 7) << 3 | 1UL << !!(error & ERR_W);
            return 0;
        }
    }

    return size;
}

Vtlb::Reason Vtlb::miss(Exc_regs *regs, mword virt, mword &error) {
    mword phys, attr = TLB_U | TLB_W | TLB_P;
    Paddr host;

    trace(TRACE_VTLB, "VTLB Miss CR3:%#010lx A:%#010lx E:%#lx", regs->cr3_shadow, virt, error);

    error &= ERR_U | ERR_W;

    size_t gsize = gwalk(regs, virt, phys, attr, error);

    if (EXPECT_FALSE(!gsize)) {
        Counter::vtlb_gpf++;
        return GLA_GPA;
    }

    size_t hsize = hwalk(phys, host, attr, error);

    if (EXPECT_FALSE(!hsize)) {
        regs->nst_fault = phys;
        regs->nst_error = error;
        Counter::vtlb_hpf++;
        return GPA_HPA;
    }

    size_t size = min(gsize, hsize);

    if (gsize > hsize)
        attr |= TLB_F;

    Counter::print<1, 16> (++Counter::vtlb_fill, Console_vga::COLOR_LIGHT_MAGENTA, SPN_VFI);

    unsigned lev = max();

    for (Vtlb *tlb = regs->vtlb;; tlb = static_cast<Vtlb *> (Buddy::phys_to_ptr(tlb->addr()))) {

        unsigned shift = --lev * bpl() + PAGE_BITS;
        tlb += virt >> shift & ((1UL << bpl()) - 1);

        if (lev) {

            if (lev == 2 || size < 1UL << shift) {

                if (tlb->super())
                    tlb->val = static_cast<typeof tlb->val> (Buddy::ptr_to_phys(new (Pd::current->quota) Vtlb) | (lev == 2 ? 0 : TLB_A | TLB_U | TLB_W) | TLB_M | TLB_P);

                else if (!tlb->present()) {
                    static_cast<Vtlb *> (Buddy::phys_to_ptr(tlb->addr()))->flush_ptab(tlb->mark());
                    tlb->val |= TLB_M | TLB_P;
                }

                tlb->val &= static_cast<typeof tlb->val> (attr | ~TLB_M);
                tlb->val |= static_cast<typeof tlb->val> (attr & TLB_F);

                continue;
            }

            if (!tlb->super())
                Vtlb::destroy(static_cast<Vtlb *> (Buddy::phys_to_ptr(tlb->addr())), Pd::current->quota);

            attr |= TLB_S;
        }

        tlb->val = static_cast<typeof tlb->val> ((host & ~((1UL << shift) - 1)) | attr | TLB_D | TLB_A);
        //        Console::print("entry end: %llx virt %lx phys %lx host: %lx error %lx", tlb->val, virt, phys, host, error);
//        Vtlb::set_cow_fault(tlb->val, phys);
        return SUCCESS;
    }
}

void Vtlb::flush_ptab(bool full) {
    for (Vtlb *e = this; e < this +(1UL << bpl()); e++) {

        if (EXPECT_TRUE(!e->present()))
            continue;

        if (EXPECT_FALSE(full))
            e->val |= TLB_M;

        else if (EXPECT_FALSE(e->mark()))
            continue;

        e->val &= ~TLB_P;
    }
}

void Vtlb::flush(mword virt) {
    unsigned l = max();

    for (Vtlb *e = this;; e = static_cast<Vtlb *> (Buddy::phys_to_ptr(e->addr()))) {

        unsigned shift = --l * bpl() + PAGE_BITS;
        e += virt >> shift & ((1UL << bpl()) - 1);

        if (!e->present())
            return;

        if (l && !e->super() && !e->frag())
            continue;

        e->val |= TLB_M;
        e->val &= ~TLB_P;

        Counter::print<1, 16> (++Counter::vtlb_flush, Console_vga::COLOR_LIGHT_RED, SPN_VFL);

        return;
    }
}

void Vtlb::flush(bool full) {
    flush_ptab(full);

    Counter::print<1, 16> (++Counter::vtlb_flush, Console_vga::COLOR_LIGHT_RED, SPN_VFL);
}

void Vtlb::set_cow_page_vmx(uint64 virt, uint64 &entry) {
    if ((virt < USER_ADDR) && (entry & TLB_P) && (entry & TLB_U)) {
        if (is_mmio(entry & ~PAGE_MASK)) {
            entry |= TLB_COW | TLB_COW_IO;
            entry &= ~TLB_P;
        } else if (entry & TLB_W) {
            entry |= TLB_COW;
            entry &= ~TLB_COW_IO;
            entry &= ~TLB_W;
        }
    }
}

void Vtlb::restore_vtlb() {
    /**
     * Consider how to put it back in pd.cpp: pd->restore_state()
     */
    Ec *ec = Ec::current;
    Pd *pd = ec->getPd();
    Lock_guard <Spinlock> guard(pd->cow_lock);
    Cow::cow_elt *cow = pd->cow_list;
    while (cow != nullptr) {
        mword a = cow->attr;
        //        a |= Vtlb::TLB_W;
        a &= ~Vtlb::TLB_W;
        *(cow->vtlb_entry) = cow->new_phys[1]->phys_addr | a;
        //        Paddr physical;
        //        mword attribut;
        //        pd->Space_mem::loc[Cpu::id].lookup(cow->page_addr_or_gpa, physical, attribut);
        //        pd->Space_mem::loc[Cpu::id].update(pd->quota, cow->page_addr_or_gpa, 0, cow->new_phys[1]->phys_addr, attribut | Hpt::HPT_W, Hpt::TYPE_UP, false);      
        //        Hpt::cow_flush(cow->page_addr_or_gpa);
        cow = cow->next;
    }
}

Cow::cow_elt *get_cow(uint64* entry, mword guest_phys){
    Ec *ec = Ec::current;
    Pd *pd = ec->getPd();
    Lock_guard <Spinlock> guard(pd->cow_lock);
    Cow::cow_elt *cow = pd->cow_list;
    while (cow != nullptr) {
        if(cow->vtlb_entry == entry && cow->page_addr_or_gpa == guest_phys)
            return cow;
        cow = cow->next;
    }
    Console::print("No Cow found ");
    return nullptr;
}
void Vtlb::set_cow_fault(uint64 &entry, mword guest_phys) {
    Ec *ec = Ec::current;
    Pd *pd = ec->getPd();
    Paddr phys = entry & ~PAGE_MASK;
    mword a = entry & PAGE_MASK;
    if (is_mmio(entry & ~PAGE_MASK)) {
        Console::print("COW in IO entry %llx, guest_phys %lx", entry, guest_phys);
        return;
    } //else 
    if (entry & TLB_W) {
        if (Ec::run_number == 1) {
            Cow::cow_elt *cow = get_cow(&entry, guest_phys & ~PAGE_MASK);
            entry = cow->new_phys[1]->phys_addr | a;
            entry |= TLB_W;
            return;
        }
        Cow::cow_elt *ce = nullptr;
        if (!Cow::get_cow_list_elt(&ce)) //get new cow_elt
            ec->die("Cow elt exhausted");

        if (pd->is_mapped_elsewhere(phys, ce) || Cow::subtitute(phys, ce, guest_phys & ~PAGE_MASK)) {
            ce->page_addr_or_gpa = guest_phys & ~PAGE_MASK;
            ce->attr = a;
            ce->vtlb_entry = &entry;
        } else // Cow::subtitute will fill cow's fields old_phys, new_phys and frame_index 
            ec->die("Cow frame exhausted");
        pd->add_cow(ce);
        ce->old_phys = phys;
        entry = ce->new_phys[0]->phys_addr | a;
        //        Paddr physical;
        //        mword attribut;
        //        pd->Space_mem::loc[Cpu::id].lookup(guest_phys, physical, attribut);
        //        pd->Space_mem::loc[Cpu::id].update(pd->quota, guest_phys, 0, ce->new_phys[0]->phys_addr, attribut | Hpt::HPT_W, Hpt::TYPE_UP, false);      
        //        Hpt::cow_flush(guest_phys);
        return;
    }
}

size_t Vtlb::vtlb_lookup(mword v, uint64 &entry) {
    unsigned lev = max();
    unsigned shift;
    Vtlb *tlb, *tlb0;
    for (tlb = this; lev; tlb = static_cast<Vtlb *> (Buddy::phys_to_ptr(tlb->addr()))) {
        if (!tlb->val)
            return 0;
        shift = --lev * bpl() + PAGE_BITS;
        tlb += v >> shift & ((1UL << bpl()) - 1);
        tlb0 = tlb;
        if (tlb->super()) break;
    }
    entry = tlb0->val;
    return 1UL << shift;
}

void Vtlb::update(Cow::cow_elt *ce) {
    ce->vtlb_entry = &this->val;
    this->val = ce->new_phys[0]->phys_addr | this->attr();
}
