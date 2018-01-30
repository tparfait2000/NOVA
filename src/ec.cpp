/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2014 Udo Steinberg, FireEye, Inc.
 * Copyright (C) 2013-2015 Alexander Boettcher, Genode Labs GmbH
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

#include "bits.hpp"
#include "ec.hpp"
#include "elf.hpp"
#include "hip.hpp"
#include "rcu.hpp"
#include "stdio.hpp"
#include "svm.hpp"
#include "vmx.hpp"
#include "vtlb.hpp"
#include "sm.hpp"
#include "pt.hpp"
#include "msr.hpp"
#include "lapic.hpp"

INIT_PRIORITY(PRIO_SLAB)
Slab_cache Ec::cache(sizeof (Ec), 32);
unsigned Ec::affich_num = 0, Ec::affich_mod = 50000, step_reason = Ec::NIL, launch_state = Ec::UNLAUNCHED;
mword Ec::prev_rip = 0, Ec::last_rip = 0, Ec::last_rcx = 0, Ec::end_rip, Ec::end_rcx, Ec::tscm1 = 0, Ec::tscm2 = 0;
bool Ec::ec_debug = false, Ec::glb_debug = false, Ec::hardening_started = false, Ec::in_rep_instruction = false, Ec::not_nul_cowlist = false, Ec::jump_ex = false;
uint64 Ec::static_tour = 0, Ec::begin_time = 0, Ec::end_time = 0, Ec::exc_counter = 0, Ec::gsi_counter1 = 0, Ec::exc_counter1 = 0, Ec::exc_counter2 = 0, Ec::lvt_counter1 = 0, Ec::msi_counter1 = 0, Ec::ipi_counter1 = 0, Ec::gsi_counter2 = 0, Ec::lvt_counter2 = 0, Ec::msi_counter2 = 0, Ec::ipi_counter2 = 0, Ec::counter1 = 0, Ec::counter2 = 0, Ec::runtime1 = 0, Ec::runtime2 = 0, Ec::total_runtime = 0, Ec::step_debug_time = 0, Ec::debug_compteur = 0, Ec::count_je = 0, Ec::nbInstr_to_execute = 0, Ec::timer_counter1 = 0, Ec::timer_counter2 = 0;
uint8 Ec::run_number = 0, Ec::launch_state = 0, Ec::step_reason = 0, Ec::debug_nb = 0;
unsigned Ec::step_nb = 200;
uint64 Ec::tsc1 = 0, Ec::tsc2 = 0; 
int Ec::previous_pmi = 0, Ec::previous_ret = 0, Ec::nb_try = 0;

Ec *Ec::current, *Ec::fpowner;
// Constructors

Cpu_regs Ec::regs_0, Ec::regs_1;

Msr_area *Ec::host_msr_area = new (Pd::kern.quota) Msr_area, *Ec::guest_msr_area = new (Pd::kern.quota) Msr_area;
Virtual_apic_page *Ec::virtual_apic_page = new (Pd::kern.quota) Virtual_apic_page;

Ec::Ec(Pd *own, void (*f)(), unsigned c, char* const nm) : Kobject(EC, static_cast<Space_obj *> (own)), cont(f), utcb(nullptr), pd(own), partner(nullptr), prev(nullptr), next(nullptr), fpu(nullptr), cpu(static_cast<uint16> (c)), glb(true), evt(0), timeout(this), user_utcb(0), xcpu_sm(nullptr), pt_oom(nullptr) {
    trace(TRACE_SYSCALL, "EC:%p created (PD:%p Kernel)", this, own);
    copy_string(name, nm);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;
}

/**
 * create en execution context 
 * @param own
 * @param sel : selector for the execution context
 * @param p : protection domain which the execution context will be bound to
 * @param f : pointer to the routine to be executed
 * @param c : cpu
 * @param e : event selector for this execution context
 * @param u : user thread control block
 * @param s : stack pointer
 */
Ec::Ec(Pd *own, mword sel, Pd *p, void (*f)(), unsigned c, unsigned e, mword u, mword s, Pt *oom, char* const nm) : Kobject(EC, static_cast<Space_obj *> (own), sel, 0xd, free, pre_free), cont(f), pd(p), partner(nullptr), prev(nullptr), next(nullptr), fpu(nullptr), cpu(static_cast<uint16> (c)), glb(!!f), evt(e), timeout(this), user_utcb(u), xcpu_sm(nullptr), pt_oom(oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);
    copy_string(name, nm);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom)
        pt_oom->add_ref();

    if (u) { // if a user thread
        //        Console::print("...user thread.");
        regs.cs = SEL_USER_CODE;
        regs.ds = SEL_USER_DATA;
        regs.es = SEL_USER_DATA;
        regs.ss = SEL_USER_DATA;
        regs.REG(fl) = Cpu::EFL_IF;
        if (glb) { // if global
            regs.REG(sp) = s;
        } else // local thread
            regs.set_sp(s);

        utcb = new (pd->quota) Utcb;

        pd->Space_mem::insert(pd->quota, u, 0, Hpt::HPT_U | Hpt::HPT_W | Hpt::HPT_P, Buddy::ptr_to_phys(utcb), true);

        regs.dst_portal = NUM_EXC - 2;

        trace(TRACE_SYSCALL, "EC:%p created (PD:%p CPU:%#x UTCB:%#lx ESP:%lx EVT:%#x)", this, p, c, u, s, e);

        if (pd == &Pd::root)
            pd->insert_utcb(pd->quota, u, Buddy::ptr_to_phys(utcb) >> 12);

    } else { //virtual CPU
        Console::print("...virtual CPU.");

        utcb = nullptr;

        regs.dst_portal = NUM_VMI - 2;
        regs.vtlb = new (pd->quota) Vtlb;

        if (Hip::feature() & Hip::FEAT_VMX) {

            regs.vmcs = new (pd->quota) Vmcs(reinterpret_cast<mword> (sys_regs() + 1),
                    pd->Space_pio::walk(pd->quota),
                    pd->loc[c].root(pd->quota),
                    pd->ept.root(pd->quota));

            regs.nst_ctrl<Vmcs>();

            /* allocate and register the host MSR area */
            mword host_msr_area_phys = Buddy::ptr_to_phys(new (pd->quota) Msr_area);
            Vmcs::write(Vmcs::EXI_MSR_LD_ADDR, host_msr_area_phys);
            Vmcs::write(Vmcs::EXI_MSR_LD_CNT, Msr_area::MSR_COUNT);

            /* allocate and register the guest MSR area */
            mword guest_msr_area_phys = Buddy::ptr_to_phys(new (pd->quota) Msr_area);
            Vmcs::write(Vmcs::ENT_MSR_LD_ADDR, guest_msr_area_phys);
            Vmcs::write(Vmcs::ENT_MSR_LD_CNT, Msr_area::MSR_COUNT);
            Vmcs::write(Vmcs::EXI_MSR_ST_ADDR, guest_msr_area_phys);
            Vmcs::write(Vmcs::EXI_MSR_ST_CNT, Msr_area::MSR_COUNT);

            /* allocate and register the virtual APIC page */
            mword virtual_apic_page_phys = Buddy::ptr_to_phys(new (pd->quota) Virtual_apic_page);
            Vmcs::write(Vmcs::APIC_VIRT_ADDR, virtual_apic_page_phys);
            regs.vmcs->clear();
            cont = send_msg<ret_user_vmresume>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCS:%p VTLB:%p)", this, p, regs.vmcs, regs.vtlb);

        } else if (Hip::feature() & Hip::FEAT_SVM) {

            regs.REG(ax) = Buddy::ptr_to_phys(regs.vmcb = new (pd->quota) Vmcb(pd->quota, pd->Space_pio::walk(pd->quota), pd->npt.root(pd->quota)));

            regs.nst_ctrl<Vmcb>();
            cont = send_msg<ret_user_vmrun>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCB:%p VTLB:%p)", this, p, regs.vmcb, regs.vtlb);
        }
    }
}

Ec::Ec(Pd *own, Pd *p, void (*f)(), unsigned c, Ec *clone, char* const nm) : Kobject(EC, static_cast<Space_obj *> (own), 0, 0xd, free, pre_free), cont(f), regs(clone->regs), rcap(clone), utcb(clone->utcb), pd(p), partner(nullptr), prev(nullptr), next(nullptr), fpu(clone->fpu), cpu(static_cast<uint16> (c)), glb(!!f), evt(clone->evt), timeout(this), user_utcb(0), xcpu_sm(clone->xcpu_sm), pt_oom(clone->pt_oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);
    copy_string(name, nm);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom)
        pt_oom->add_ref();
}

//De-constructor

Ec::~Ec() {
    pre_free(this);

    if (pt_oom && pt_oom->del_ref())
        Pt::destroy(pt_oom, pd->quota);

    if (fpu)
        Fpu::destroy(fpu, pd->quota);

    if (utcb) {
        Utcb::destroy(utcb, pd->quota);
        return;
    }

    /* skip xCPU EC */
    if (!regs.vtlb)
        return;

    /* vCPU cleanup */
    Vtlb::destroy(regs.vtlb, pd->quota);

    if (Hip::feature() & Hip::FEAT_VMX) {

        regs.vmcs->make_current();

        mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
        Msr_area *host_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
        Msr_area::destroy(host_msr_area, pd->quota);

        mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
        Msr_area *guest_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
        Msr_area::destroy(guest_msr_area, pd->quota);

        mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
        Virtual_apic_page *virtual_apic_page =
                reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
        Virtual_apic_page::destroy(virtual_apic_page, pd->quota);

        regs.vmcs->clear();

        Vmcs::destroy(regs.vmcs, pd->quota);
    } else if (Hip::feature() & Hip::FEAT_SVM)
        Vmcb::destroy(regs.vmcb, pd->quota);
}

void Ec::handle_hazard(mword hzd, void (*func)()) {
    if (hzd & HZD_RCU)
        Rcu::quiet();

    if (hzd & HZD_SCHED && is_idle()) {
        current->cont = func;
        Sc::schedule();
    }

    if (hzd & HZD_RECALL) {
        current->regs.clr_hazard(HZD_RECALL);

        if (func == ret_user_vmresume) {
            current->regs.dst_portal = NUM_VMI - 1;
            send_msg<ret_user_vmresume>();
        }

        if (func == ret_user_vmrun) {
            current->regs.dst_portal = NUM_VMI - 1;
            send_msg<ret_user_vmrun>();
        }

        if (func == ret_user_sysexit)
            current->redirect_to_iret();

        current->regs.dst_portal = NUM_EXC - 1;
        send_msg<ret_user_iret>();
    }

    if (hzd & HZD_STEP) {
        current->regs.clr_hazard(HZD_STEP);

        if (func == ret_user_sysexit)
            current->redirect_to_iret();

        current->regs.dst_portal = Cpu::EXC_DB;
        send_msg<ret_user_iret>();
    }

    if (hzd & HZD_TSC) {
        current->regs.clr_hazard(HZD_TSC);

        if (func == ret_user_vmresume) {
            //Console::print("TSC_OFFSET");
            current->regs.vmcs->make_current();
            Vmcs::write(Vmcs::TSC_OFFSET, static_cast<mword> (current->regs.tsc_offset));
            Vmcs::write(Vmcs::TSC_OFFSET_HI, static_cast<mword> (current->regs.tsc_offset >> 32));
        } else
            current->regs.vmcb->tsc_offset = current->regs.tsc_offset;
    }

    if (hzd & HZD_DS_ES) {
        Cpu::hazard &= ~HZD_DS_ES;
        asm volatile ("mov %0, %%ds; mov %0, %%es" : : "r" (SEL_USER_DATA));
    }

    if (hzd & HZD_FPU)
        if (current != fpowner)
            Fpu::disable();
}

void Ec::ret_user_sysexit() {
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | HZD_FPU | HZD_DS_ES | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_sysexit);

        current->save_state();
        launch_state = Ec::SYSEXIT;
        begin_time = rdtsc(); //normalement, cette instruction devrait etre dans le if precedant
    }
    //    if(!strcmp(current->get_name(), "fb_drv")){
    //        count_je++;
    //    }
    //        mword *p = reinterpret_cast<mword*> (0x18028);
    //        Paddr physical_addr;
    //        mword attribut;
    //        size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
    //        if(count_je > 0x1a6){
    //            if(is_mapped)
    //                Console::print("value phys %lx 18028: %lx", physical_addr, reinterpret_cast<mword>(*p));
    //            else
    //                Console::print("Not mapped phys %lx jump %llx", physical_addr, count_je);
    //        }

    if (!strcmp(current->get_name(), "fb_drv")) {
        //        debug_func("Sysreting");
        mword *v = reinterpret_cast<mword*> (0x18028);
        Paddr physical_addr;
        mword attribut;
        size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
        if (is_mapped && (*v != 0x8020)) {
            //            current->getPd()->loc[Cpu::id].update(current->getPd()->quota, reinterpret_cast<mword> (v), 0, physical_addr, attribut, Hpt::TYPE_UP, false);
            current->getPd()->loc[Cpu::id].flush(reinterpret_cast<mword> (v));
            Console::print("Rectifying in Sysret PD: %s EC %s EIP %lx phys %lx 18028:%lx", Pd::current->get_name(), current->get_name(), current->regs.REG(ip), physical_addr, *v);
        }
    }
    //    if(!strcmp(current->get_name(), "fb_drv") && current->regs.REG(cx) == 0x1024852 && (current->regs.r8 == 0x8824a70 || current->regs.r8 == 0x8824a74)){
    //        mword *p = reinterpret_cast<mword*> (0x18028);
    //        Console::print("EIP = SYSRETING PD: %s EC %s step_reason %d 0x18028: %lx", Pd::current->get_name(), current->get_name(), step_reason, *p);
    ////        Cpu_regs reg_d = current->regs;
    ////        Console::print("eip: %lx  rax %lx  rbx %lx  rcx %lx  rdx %lx esp %lx  rbp %lx  rdix %lx r8 %lx r9 %lx r10 %lx r11 %lx r12 %lx r13 %lx r14 %lx r15 %lx", 
    ////                reg_d.REG(ip), reg_d.REG(ax), reg_d.REG(bx), reg_d.REG(cx), reg_d.REG(dx), reg_d.REG(sp), reg_d.REG(bp), reg_d.REG(di), reg_d.r8, reg_d.r9, reg_d.r10, reg_d.r11, reg_d.r12, reg_d.r13, reg_d.r14, reg_d.r15);
    ////        Console::print("r8 %lx",  reg_d.r8);
    //        debug = true;
    //        step_reason = GP;
    //        current->regs.REG(fl) |= Cpu::EFL_TF;
    ////        Lapic::reset_counter(0xe3184);
    //    }else if(debug){
    //        Console::print("DEBUG SYSRETING PD: %s EC %s EIP %lx step_reason %d r8 %lx", Pd::current->get_name(), current->get_name(), current->regs.REG(cx), step_reason, current->regs.r8);
    //    }
    //    
    debug_print("Sysreting");
    if (step_reason == NIL) {
        asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR RET_USER_HYP) : : "m" (current->regs) : "memory");
    } else {
        asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR RET_USER_HYP_SS) : : "m" (current->regs) : "memory");
    }
    UNREACHED;
}

void Ec::ret_user_iret() {
    if (is_idle()) {
        // No need to check HZD_DS_ES because IRET will reload both anyway
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | HZD_FPU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_iret);

        current->save_state();
        launch_state = Ec::IRET;
        begin_time = rdtsc();
    }
    if (!strcmp(current->get_name(), "fb_drv")) {
        //        debug_func("Ireting");
        mword *v = reinterpret_cast<mword*> (0x18028);
        Paddr physical_addr;
        mword attribut;
        size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
        if (is_mapped && (*v != 0x8020)) {
            //            current->getPd()->loc[Cpu::id].update(current->getPd()->quota, reinterpret_cast<mword> (v), 0, physical_addr, attribut, Hpt::TYPE_UP, false);
            current->getPd()->loc[Cpu::id].flush(reinterpret_cast<mword> (v));
            Console::print("Rectifying in Iret PD: %s EC %s EIP %lx phys %lx 18028:%lx", Pd::current->get_name(), current->get_name(), current->regs.REG(ip), physical_addr, *v);
        }
    }


    debug_print("Ireting");
    //    if (!strcmp(current->get_name(), "fb_drv")) {
    //        mword *p = reinterpret_cast<mword*> (0x18028);
    //        Paddr physical_addr;
    //        mword attribut;
    //        size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
    //        if (is_mapped) {
    //            Console::print("Ireting PD: %s EC %s EIP %lx phys %lx 18028:%lx", Pd::current->get_name(), current->get_name(), current->regs.REG(ip), physical_addr, *p);
    //        } else
    //            Console::print("Not mapped phys");
    //    }
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR LOAD_SEG RET_USER_EXC) : : "m" (current->regs) : "memory");

    UNREACHED;
}

void Ec::chk_kern_preempt() {
    if (!Cpu::preemption)
        return;

    if (is_idle() && Cpu::hazard & HZD_SCHED) { // this may leak from the kernel without terminating a double_running.
        Cpu::preempt_disable();
        Sc::schedule();
    }
}

void Ec::ret_user_vmresume() {
    //    Console::print("VMRun is_idle %d", is_idle());
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmresume);

        current->regs.vmcs->make_current();

        current->vmx_save_state();
        launch_state = Ec::VMRESUME;
        Lapic::program_pmi();
    }

    if (EXPECT_FALSE(Pd::current->gtlb.chk(Cpu::id))) {
        Pd::current->gtlb.clr(Cpu::id);
        if (current->regs.nst_on)
            Pd::current->ept.flush();
        else
            current->regs.vtlb->flush(true);
    }

    if (EXPECT_FALSE(get_cr2() != current->regs.cr2))
        set_cr2(current->regs.cr2);
    if (ec_debug)
        Console::print("VMRun vRIP %lx", Vmcs::read(Vmcs::GUEST_RIP));
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xb);
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR)
                "vmresume;"
                "vmlaunch;"
                "mov %1," EXPAND(PREG(sp);)
                : : "m" (current->regs), "i" (CPU_LOCAL_STCK + PAGE_SIZE) : "memory");

    trace(0, "VM entry failed with error %#lx", Vmcs::read(Vmcs::VMX_INST_ERROR));

    die("VMENTRY");
}

void Ec::ret_user_vmrun() {
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmrun);

        //        current->svm_save_state();
        launch_state = Ec::VMRUN;
    }
    if (EXPECT_FALSE(Pd::current->gtlb.chk(Cpu::id))) {
        Pd::current->gtlb.clr(Cpu::id);
        if (current->regs.nst_on)
            current->regs.vmcb->tlb_control = 1;
        else
            current->regs.vtlb->flush(true);
    }
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR)
                "clgi;"
                "sti;"
                "vmload;"
                "vmrun;"
                "vmsave;"
                EXPAND(SAVE_GPR)
                "mov %1," EXPAND(PREG(ax);)
                "mov %2," EXPAND(PREG(sp);)
                "vmload;"
                "cli;"
                "stgi;"
                "jmp svm_handler;"
                : : "m" (current->regs), "m" (Vmcb::root), "i" (CPU_LOCAL_STCK + PAGE_SIZE) : "memory");

    UNREACHED;
}

void Ec::idle() {
    for (;;) {

        mword hzd = Cpu::hazard & (HZD_RCU | HZD_SCHED);
        if (is_idle() && EXPECT_FALSE(hzd))
            handle_hazard(hzd, idle);

        uint64 t1 = rdtsc();
        asm volatile ("sti; hlt; cli" : : : "memory");
        uint64 t2 = rdtsc();

        Counter::cycles_idle += t2 - t1;
    }
}

void Ec::root_invoke() {
    Eh *e = static_cast<Eh *> (Hpt::remap(Pd::kern.quota, Hip::root_addr));
    if (!Hip::root_addr || e->ei_magic != 0x464c457f || e->ei_class != ELF_CLASS || e->ei_data != 1 || e->type != 2 || e->machine != ELF_MACHINE)
        die("No ELF");

    unsigned count = e->ph_count;
    current->regs.set_pt(Cpu::id);
    current->regs.set_ip(e->entry);
    current->regs.set_sp(USER_ADDR - PAGE_SIZE);

    ELF_PHDR *p = static_cast<ELF_PHDR *> (Hpt::remap(Pd::kern.quota, Hip::root_addr + e->ph_offset));

    for (unsigned i = 0; i < count; i++, p++) {

        if (p->type == 1) {

            unsigned attr = !!(p->flags & 0x4) << 0 | // R
                    !!(p->flags & 0x2) << 1 | // W
                    !!(p->flags & 0x1) << 2; // X

            if (p->f_size != p->m_size || p->v_addr % PAGE_SIZE != p->f_offs % PAGE_SIZE)
                die("Bad ELF");

            mword phys = align_dn(p->f_offs + Hip::root_addr, PAGE_SIZE);
            mword virt = align_dn(p->v_addr, PAGE_SIZE);
            mword size = align_up(p->f_size, PAGE_SIZE);

            for (unsigned long o; size; size -= 1UL << o, phys += 1UL << o, virt += 1UL << o)
                Pd::current->delegate<Space_mem>(&Pd::kern, phys >> PAGE_BITS, virt >> PAGE_BITS, (o = min(max_order(phys, size), max_order(virt, size))) - PAGE_BITS, attr);
        }
    }

    // Map hypervisor information page
    Pd::current->delegate<Space_mem>(&Pd::kern, reinterpret_cast<Paddr> (&FRAME_H) >> PAGE_BITS, (USER_ADDR - PAGE_SIZE) >> PAGE_BITS, 0, 1);

    Space_obj::insert_root(Pd::kern.quota, Pd::current);
    Space_obj::insert_root(Pd::kern.quota, Ec::current);
    Space_obj::insert_root(Pd::kern.quota, Sc::current);

    /* adjust root quota used by Pd::kern during bootstrap */
    Quota::boot(Pd::kern.quota, Pd::root.quota);

    /* preserve per CPU 4 pages quota */
    Quota cpus;
    bool s = Pd::root.quota.transfer_to(cpus, Cpu::online * 4);
    assert(s);

    /* preserve for the root task memory that is not transferable */
    bool res = Pd::root.quota.set_limit((1 * 1024 * 1024) >> 12, 0, Pd::root.quota);
    assert(res);

    /* setup PCID handling */
    Space_mem::boot_init();
    assert(Pd::kern.did == 0);
    assert(Pd::root.did == 1);

    /* quirk */
    if (Dpt::ord != ~0UL && Dpt::ord > 0x8) {
        trace(0, "disabling super pages for DMAR");
        Dpt::ord = 0x8;
    }

    ret_user_sysexit();
}

void Ec::handle_tss() {
    Console::panic("Task gate invoked");
}

bool Ec::fixup(mword &eip) {
    for (mword *ptr = &FIXUP_S; ptr < &FIXUP_E; ptr += 2)
        if (eip == *ptr) {
            eip = *++ptr;
            return true;
        }

    return false;
}

void Ec::die(char const *reason, Exc_regs *r) {
//    backtrace();
    if (current->utcb || current->pd == &Pd::kern) {
        if (strcmp(reason, "PT not found"))
            trace(0, "Killed EC:%p SC:%p V:%#lx CS:%#lx EIP:%#lx CR2:%#lx ERR:%#lx (%s) Pd: %s Ec: %s",
                current, Sc::current, r->vec, r->cs, r->REG(ip), r->cr2, r->err, reason, Pd::current->get_name(), Ec::current->get_name());
    } else
        trace(0, "Killed EC:%p SC:%p V:%#lx CR0:%#lx CR3:%#lx CR4:%#lx (%s) Pd: %s Ec: %s",
            current, Sc::current, r->vec, r->cr0_shadow, r->cr3_shadow, r->cr4_shadow, reason, Pd::current->get_name(), Ec::current->get_name());

    Ec *ec = current->rcap;

    if (ec)
        ec->cont = ec->cont == ret_user_sysexit ? static_cast<void (*)()> (sys_finish<Sys_regs::COM_ABT>) : dead;

    reply(dead);
}

void Ec::xcpu_return() {
    assert(current->xcpu_sm);
    assert(current->rcap);
    assert(current->utcb);
    assert(Sc::current->ec == current);

    current->rcap->regs = current->regs;

    current->xcpu_sm->up(ret_xcpu_reply);

    current->rcap = nullptr;
    current->utcb = nullptr;
    current->fpu = nullptr;

    Rcu::call(current);
    Rcu::call(Sc::current);

    Sc::schedule(true);
}

void Ec::idl_handler() {
    if (Ec::current->cont == Ec::idle)
        Rcu::update();
}

bool Ec::is_temporal_exc() {
    mword v = regs.REG(ip);
    uint16 *ptr = reinterpret_cast<uint16 *> (v);
    if (*ptr == 0x310f) {// rdtsc 0f 31
        return true;
    } else if (*ptr == 0xf901) {// rdtscp 0F 01 F9
        return true;
    } else
        return false;
}

bool Ec::is_io_exc(mword eip) {
    /*TODO
     * Firstly we must ensure that the port the process is trying to access is 
     * within its I/O port space
     * We must also deal with the REP prefix: solved because rep prefix makes instr code = 6cf3, 6df3 e4f3 ...
     */
    mword v = eip ? eip : regs.REG(ip);
    uint8 *ptr = reinterpret_cast<uint8 *> (v);
    switch (*ptr) {
        case 0xe4: // IN AL, imm8
        case 0xe5: // IN AX, imm8 || IN EAX, imm8
        case 0xe6: // OUT imm8, AL
        case 0xe7: // OUT imm8, AX || OUT imm8, EAX
        case 0xec: // IN AL,DX
            //            uint8 io_port = reinterpret_cast<uint8 *> (r->REG(dx));
        case 0xed: // IN AX, || IN EAX,DX
        case 0xee: // OUT DX, AL
        case 0xef: // OUT DX, AX || OUT DX, EAX
        case 0x6c: // INS m8, DX || INSB 
        case 0x6d: // INS m16, DX || INS m32, DX || INSW || INSD
        case 0x6e: // OUTS DX, m8 || OUTSB
        case 0x6f: // OUTS DX, m16 || OUTS DX, m32 || OUTSW || OUTSD
            return true;
        case 0x66:
        case 0x67:
            return is_io_exc(v + 1); // operand-size prefixe
        default:
            return false;
    }
}

void Ec::resolve_PIO_execption() {
    //    Console::print("Read PIO");
    reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->enable_pio(Pd::current->quota);
    Ec::current->enable_step_debug(PIO, SPC_LOCAL_IOP, 0, 0);
}

//void Ec::resolve_temp_exception() {
//    //    Console::print("Read TSC Ec: %p, is_idle(): %d  IP: %p", current, is_idle(), current->regs.REG(ip));
//    set_cr4(get_cr4() & ~Cpu::CR4_TSD);
//    Ec::current->enable_step_debug(0, 0, 0, Step_reason::RDTSC);
//}

void Ec::enable_step_debug(Step_reason reason, mword fault_addr, Paddr fault_phys, mword fault_attr) {
    regs.REG(fl) |= Cpu::EFL_TF;
    step_reason = reason;
    switch (reason) {
        case PIO:
        case MMIO:
            io_addr = fault_addr;
            io_phys = fault_phys;
            io_attr = fault_attr;
            launch_state = Launch_type::IRET; // to ensure that this will finished before any other thread is scheduled
            break;
        case RDTSC:
            set_cr4(get_cr4() & ~Cpu::CR4_TSD);
            launch_state = Launch_type::IRET; // to ensure that this will finished before any other thread is scheduled
            break;
        case PMI:
            //        {
            //            uint8 *ptr = reinterpret_cast<uint8 *> (end_rip);
            //            if (*ptr == 0xf3 || *ptr == 0xf2) {
            ////                Console::print("Rep prefix detected");
            //                in_rep_instruction = true;
            //                Cpu::disable_fast_string();
            //            }
            break;
            //        }
        case NIL:
        default:
            Console::print("Unknown debug reason -- Enable");
            die("Unknown debug reason -- Enable");
            break;
    }
}

void Ec::disable_step_debug() {
    regs.REG(fl) &= ~Cpu::EFL_TF;
    switch (step_reason) {
        case MMIO:
            //            Console::print("MMIO read");
            Pd::current->loc[Cpu::id].replace_cow(Pd::current->quota, io_addr, io_phys | (io_attr & ~Hpt::HPT_P));
            Hpt::cow_flush(io_addr);
            break;
        case PIO:
//                        Console::print("PIO read");
            reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->disable_pio(Pd::current->quota);
            break;
        case RDTSC:
            //            Console::print("TSC read Ec: %p, is_idle(): %d  IP: %p", current, is_idle(), current->regs.REG(ip));
            set_cr4(get_cr4() | Cpu::CR4_TSD);
            break;
        case PMI:
            if (in_rep_instruction) {
                Cpu::enable_fast_string();
                in_rep_instruction = false;
            }
            nbInstr_to_execute = 0;
            break;
        default:
            Console::print("Unknown debug reason -- Disable");
            break;
    }
    step_reason = NIL;
}

void Ec::restore_state() {
    regs_1 = regs;
    regs = regs_0;
    Fpu::dwc_restore();
    if (fpu)
        fpu->restore_data();
    if (utcb)
        pd->restore_state();
    else
        regs.vtlb->restore_vtlb();
    reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->enable_pio(Pd::current->quota);    
}

void Ec::rollback() {
    regs = regs_0;
    Fpu::dwc_rollback();
    if (fpu)
        fpu->roll_back();
    pd->rollback(!static_cast<bool>(utcb));
    if (!utcb) {
        regs.vmcs->clear();
        memcpy(current->regs.vmcs, Vmcs::vmcs0, Vmcs::basic.size);
        regs.vmcs->make_current();
    }
    reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->disable_pio(Pd::current->quota);    
}

void Ec::saveRegs(Exc_regs *r) {
    if (r->cs & 3) {
        end_time = rdtsc();
        last_rip = r->REG(ip);
        last_rcx = r->REG(cx);
        exc_counter++;
        //        if(ec_debug)
        //        Console::print("vector: %lu  cs: %lx  rip: %lx  rcx: %lx  instr %llu", r->vec, r->cs, r->REG(ip), r->REG(cx), Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0));
    }
    return;
}

void Ec::save_state() {
    regs_0 = regs;
    Fpu::dwc_save();        
    if (fpu)
        fpu->save_data();
    reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->disable_pio(Pd::current->quota);
}

void Ec::vmx_save_state() {
    save_state();
    //    save_vm_stack();
    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(host_msr_area, cur_host_msr_area, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(guest_msr_area, cur_guest_msr_area, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(virtual_apic_page, cur_virtual_apic_page, PAGE_SIZE);
    
    regs.vmcs->clear();
    memcpy(Vmcs::vmcs0, regs.vmcs, Vmcs::basic.size);
    regs.vmcs->make_current();
}

void Ec::vmx_restore_state() {
    restore_state();
    
    regs.vmcs->clear();
    memcpy(regs.vmcs, Vmcs::vmcs0, Vmcs::basic.size);
    regs.vmcs->make_current();
    
    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(cur_host_msr_area, host_msr_area, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(cur_guest_msr_area, guest_msr_area, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(cur_virtual_apic_page, virtual_apic_page, PAGE_SIZE);
}

mword Ec::get_regsRIP() {
    return regs.REG(ip);
}

mword Ec::get_regsRCX() {
    return regs.REG(cx);
}

int Ec::compare_regs(int reason) {
    if (regs.r15 != regs_1.r15)
        return 1;
    if (regs.r14 != regs_1.r14)
        return 2;
    if (regs.r13 != regs_1.r13)
        return 3;
    if (regs.r12 != regs_1.r12)
        return 4;
    if (regs.r11 != regs_1.r11) {
        // resume flag  or trap flag may be set if reason is step-mode
        // but it is unclear why. Must be fixed later
        if (((regs.r11 | 1u << 16) == regs_1.r11) || (regs.r11 == (regs_1.r11 | 1u << 8)))
            return 0;
        else {
            Console::print("R11: %lx  R11_1: %lx  R11or1: %lx", regs.r11, regs_1.r11, regs.r11 | 1u << 8);
            return 5;
        }
    }
    if (regs.r10 != regs_1.r10)
        return 6;
    if (regs.r9 != regs_1.r9)
        return 7;
    if (regs.r8 != regs_1.r8)
        return 8;
    if (regs.REG(di) != regs_1.REG(di))
        return 9;
    if (regs.REG(si) != regs_1.REG(si))
        return 10;
    if (regs.REG(bp) != regs_1.REG(bp))
        return 11;
    if (regs.REG(bx) != regs_1.REG(bx))
        return 12;
    if (regs.REG(cx) != regs_1.REG(cx))
        return 13;
    if (regs.REG(dx) != regs_1.REG(dx))
        return 14;
    if (regs.REG(ax) != regs_1.REG(ax))
        return 15;
    if (fpu && fpu->data_check()) 
        return 16;
    if(Fpu::dwc_check())
        return 17;
    if (reason == 1258 || !utcb) // following checks are not valid if reason is Sysenter or current is vCPU
        return 0;
    if ((regs.REG(ip) != regs_1.REG(ip)))
        return 18;
    if ((regs.REG(fl) != regs_1.REG(fl)) && ((regs.REG(fl) | (1u << 16)) != regs_1.REG(fl)))
        // resume flag may be set if reason is step-mode but it is curious why this flag is set in regs_1 and not in regs.
        // the contrary would be understandable. Must be fixed later
        return 19;
    if (regs.REG(sp) != regs_1.REG(sp))
        return 20;
    return 0;
}

void Ec::Setx86DebugReg(mword addr, int dr) {
    mword dr7 = 0; // or 0x4aa or 0x7aa or 0x6aa 
    switch (dr) {
        default:
        case 0:
            asm volatile ("mov %0, %%dr0"::"r"(addr));
            dr7 = 0x000D07aa;
            break;
        case 1:
            asm volatile ("mov %0, %%dr1" : : "r"(addr));
            dr7 = 0x00D00004;
            break;
        case 2:
            asm volatile ("mov %0, %%dr2"::"r"(addr));
            dr7 = 0x0D000010;
            break;
        case 3:
            dr7 = 0xD0000040;
            asm volatile ("mov %0, %%dr3"::"r"(addr));
    }
    asm volatile ("mov %0, %%dr7"::"r"(dr7));
    return;
}

void Ec::debug_func(const char* source) {
    mword rip;
    if (strcmp(source, "Ireting"))
        rip = current->regs.REG(cx);
    else
        rip = current->regs.REG(ip);
    Console::print("%s PD: %s EC %s EIP %lx rcx %lx counter %llx exc %lld", source, Pd::current->get_name(), current->get_name(), rip, current->regs.REG(cx), Lapic::read_instCounter(), exc_counter);
}

void Ec::debug_print(const char* source) {
    if (glb_debug || current->getPd()->pd_debug || current->debug)
        debug_func(source);
    return;

}

ALWAYS_INLINE
static inline mword read_ebp() {
    mword ebp;
    asm volatile("mov " EXPAND(PREG(bp)) ",%0" : "=r" (ebp));
    return ebp;
}

/**
 * Only valable on 32 bits
 */
void Ec::backtrace(int depth) {
    mword ebp = read_ebp(), eip = 0;
    mword* ebpp;
    Console::print("Stack backtrace:");
    int tour = 0;
    while (ebp && (tour < depth)) {//if ebp is 0, we are back at the first caller
        ebpp = reinterpret_cast<mword*> (ebp);
        eip = *(ebpp + 1);
        char args[60];
        int argno = 0;
        for (; argno < 5; argno++) {
            Console::sprint(args, "%lx ", *(ebpp + 2 + argno));
        }

        Console::print("ebp %lx eip %lx args %s (ebp) %lx", ebp, eip, args, *ebpp);

        ebp = *ebpp;
        tour++;
    }
    return;
}

void Ec::save_stack() {
    /**
     * @TODO
     * Because we know  it's about the stack, we can save time by doing this only the first time.
     * This imply never set it Read-Only when we are writing the memory back at commitment time.
     * What if guest_virt != guest_phys? 
     * Include vtlb in this
     */
    Paddr phys;
    mword a;
    mword v;
    v = regs.REG(sp) & ~PAGE_MASK;
    if (!pd->Space_mem::loc[Cpu::id].lookup(v, phys, a)) return;
    Cow::cow_elt *ce = nullptr;
    if (!Cow::get_cow_list_elt(&ce)) //get new cow_elt
        die("Cow elt exhausted");
    if (pd->is_mapped_elsewhere(phys, ce) || Cow::subtitute(phys, ce, v)) {
        ce->page_addr_or_gpa = v;
        ce->attr = a;
    } else // Cow::subtitute will fill cow's fields old_phys, new_phys and frame_index 
        die("Cow frame exhausted");
    pd->add_cow(ce);
    pd->Space_mem::loc[Cpu::id].update(pd->quota, v, 0, ce->new_phys[0]->phys_addr, a | Hpt::HPT_W, Hpt::Type::TYPE_UP, false);
    Hpt::cow_flush(v);
}

void Ec::save_vm_stack() {
    /**
     * @TODO
     * Because we know  it's about the stack, we can save time by doing this only the first time.
     * This imply never set it Read-Only when we are writing the memory back at commitment time.
     * What if guest_virt != guest_phys? 
     * Include vtlb in this
     */
    Paddr host_phys;
    mword host_attr, guest_phys, guest_attr, guest_rsp = Vmcs::read(Vmcs::GUEST_RSP) & ~PAGE_MASK;
    uint64 entry;
    if (!regs.vtlb->vtlb_lookup(guest_rsp, entry)) return;
    if (!regs.guest_lookup(guest_rsp, guest_phys, guest_attr)) {
        Console::print("Pas normal guest_rsp %lx guest_phys %lx guest_attr %lx", guest_rsp, guest_phys, guest_attr);
        return;
    }
    if (!pd->Space_mem::loc[Cpu::id].lookup(guest_phys, host_phys, host_attr)) return;
    if (!(host_attr & Hpt::HPT_W) || !(entry & Vtlb::TLB_W)) {
        Console::print("Pas writable");
        return;
    }
    Cow::cow_elt *ce = nullptr;
    if (!Cow::get_cow_list_elt(&ce)) //get new cow_elt
        die("Cow elt exhausted");
    if (pd->is_mapped_elsewhere(host_phys, ce) || Cow::subtitute(host_phys, ce, guest_phys)) {
        ce->page_addr_or_gpa = guest_phys;
        ce->attr = host_attr;
        regs.vtlb->update(ce);
    } else // Cow::subtitute will fill cow's fields old_phys, new_phys and frame_index 
        die("Cow frame exhausted");
    pd->add_cow(ce);
    pd->Space_mem::loc[Cpu::id].update(pd->quota, guest_phys, 0, ce->new_phys[0]->phys_addr, host_attr | Hpt::HPT_W, Hpt::Type::TYPE_UP, false);
    Hpt::cow_flush(guest_phys);
}