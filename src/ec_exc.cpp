/*
 * Execution Context
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

#include "ec.hpp"
#include "gdt.hpp"
#include "mca.hpp"
#include "stdio.hpp"
#include "msr.hpp"

void Ec::load_fpu() {
    if (!utcb)
        regs.fpu_ctrl(true);

    if (EXPECT_FALSE(!fpu))
        Fpu::init();
    else
        fpu->load();
}

void Ec::save_fpu() {
    if (EXPECT_FALSE(!this))
        return;

    if (!utcb)
        regs.fpu_ctrl(false);

    if (EXPECT_FALSE(!fpu))
        fpu = new (pd->quota) Fpu;

    fpu->save();
}

void Ec::transfer_fpu(Ec *ec) {
    if ((!utcb && !regs.fpu_on) ||
            (!ec->utcb && !ec->regs.fpu_on))
        return;

    if (!(Cpu::hazard & HZD_FPU)) {

        Fpu::enable();

        if (fpowner != this) {
            fpowner->save_fpu();
            load_fpu();
        }
    }

    if (fpowner && fpowner->del_ref())
        delete fpowner;

    fpowner = ec;
    fpowner->add_ref();
}

void Ec::handle_exc_nm() {
    Fpu::enable();

    if (current == fpowner)
        return;

    fpowner->save_fpu();
    current->load_fpu();

    if (fpowner && fpowner->del_ref())
        delete fpowner;

    fpowner = current;
    fpowner->add_ref();
}

bool Ec::handle_exc_ts(Exc_regs *r) {
    if (r->user()) {
        check_memory(1259);
        return false;
    }
    // SYSENTER with EFLAGS.NT=1 and IRET faulted
    r->REG(fl) &= ~Cpu::EFL_NT;

    return true;
}

bool Ec::handle_exc_gp(Exc_regs *r) {
    if (r->user())
        check_memory(1252);
    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }

    mword eip = r->REG(ip);
    if (current->is_temporal_exc(eip)) {
        current->resolve_temp_exception();
        return true;
    } else if (current->is_io_exc(eip)) {
        current->resolve_PIO_execption();
        return true;
    }
    Console::print("GP Here: addr: %08lx", eip);
    return false;
}

bool Ec::handle_exc_pf(Exc_regs *r) {
    mword addr = r->cr2;
    
    if ((r->err & Hpt::ERR_U) && Pd::current->Space_mem::loc[Cpu::id].is_cow_fault(Pd::current->quota, addr, r->err))
        return true;

    check_memory(1254);
    if (r->err & Hpt::ERR_U)
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR);

    if (addr < USER_ADDR) {

        if (Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR))
            return true;

        if (fixup(r->REG(ip))) {
            r->REG(ax) = addr;
            return true;
        }
    }

    if (addr >= LINK_ADDR && addr < CPU_LOCAL && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Hptp(reinterpret_cast<mword> (&PDBR)), addr, CPU_LOCAL))
        return true;

    // Kernel fault in I/O space
    if (addr >= SPC_LOCAL_IOP && addr <= SPC_LOCAL_IOP_E) {
        Space_pio::page_fault(addr, r->err);
        return true;
    }

    // Kernel fault in OBJ space
    if (addr >= SPC_LOCAL_OBJ) {
        Space_obj::page_fault(addr, r->err);
        return true;
    }

    die("#PF (kernel)", r);
}

void Ec::handle_exc(Exc_regs *r) {
    Counter::exc[r->vec]++;

    switch (r->vec) {
        case Cpu::EXC_DB:
            //            Console::print("DEBUG");
            if (r->user()) {
                Ec::current->disable_step_debug();
                current->launch_state = Ec::UNLAUNCHED;
                return;
            } else {
                Console::print("Debug in kernel");
                break;
            }

        case Cpu::EXC_NM:
            if (r->user())
                check_memory(1253);
            handle_exc_nm();
            return;

        case Cpu::EXC_TS:
            if (handle_exc_ts(r))
                return;
            break;

        case Cpu::EXC_GP:
            if (handle_exc_gp(r))
                return;
            break;

        case Cpu::EXC_PF:
            if (handle_exc_pf(r))
                return;
            break;

        case Cpu::EXC_MC:
            Mca::vector();
            break;
    }

    if (r->user()) {
        check_memory(1256);
        send_msg<ret_user_iret>();
    }

    die("EXC", r);
}

void Ec::check_memory(int pmi) {
    Ec *ec = current;
    Pd *pd = ec->getPd();
    if (ec->is_idle() || !pd->cow_list) {
        ec->run_number = 0;
        ec->launch_state = Ec::UNLAUNCHED;
        return;
    }
    //    if (!current->user_utcb) {
    //        Console::print(".....  Checking memory from %d. eip: %p", from, Ec::current->regs.REG(ip));
    //        current->ec_debug= true;
    //    }
//    Console::print(".....  Checking memory from %d  Ec: %p", pmi, ec);
    if (ec->one_run_ok()) {
       if (pd->compare_and_commit()) {
            ec->run_number = 0;
            ec->launch_state = Ec::UNLAUNCHED;
            pd->cow_list = nullptr;
            return;
        } else {
            Console::print("Checking failed Ec: %p", ec);
            ec->rollback();
            ec->run_number = 0;
            pd->cow_list = nullptr;
            switch (ec->launch_state) {
                case Ec::SYSEXIT:
                    Ec::ret_user_sysexit();
                    break;
                case Ec::IRET:
                    Ec::ret_user_iret();
                case Ec::VMRESUME:
                    Ec::ret_user_vmresume();
                case Ec::VMRUN:
                    Ec::ret_user_vmrun();
                case Ec::UNLAUNCHED:
                    Console::print("Bad Run");
                    Ec::die("Bad Run");
            }
        }
    } else {
        ec->restore_state();
        ec->run_number++;
        switch (ec->launch_state) {
            case Ec::SYSEXIT:
                Ec::ret_user_sysexit();
                break;
            case Ec::IRET:
                Ec::ret_user_iret();
            case Ec::VMRESUME:
                Ec::ret_user_vmresume();
            case Ec::VMRUN:
                Ec::ret_user_vmrun();
            case Ec::UNLAUNCHED:
                Console::print("Bad Run");
                Ec::die("Bad Run");
        }
    }

    //        /*when atomic sequence is executed in parallel, it is an other EC which 
    //         should be picked. Make sure this is respected*/
    //        Sc::schedule();
    return;
}