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
    if (r->user())
        return false;

    // SYSENTER with EFLAGS.NT=1 and IRET faulted
    r->REG(fl) &= ~Cpu::EFL_NT;

    return true;
}

bool Ec::handle_exc_gp(Exc_regs *r) {
    //if (r->user() || (r->err & Hpt::ERR_U))

    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }
    check_memory();

    mword addr = r->REG(ip);
    if (current->is_temporal_exc(addr)) {
        current->resolve_temp_exception();
        return true;
    } else if (current->is_io_exc(addr)) {
        current->resolve_PIO_execption();
        return true;
    }
    Console::print("GP Here: addr: %08lx", addr);
    return false;
}

bool Ec::handle_exc_pf(Exc_regs *r) {
    mword addr = r->cr2;
    
    if ((r->err & Hpt::ERR_U) && Pd::current->Space_mem::loc[Cpu::id].is_cow_fault(Pd::current->quota, addr, r->err))
        return true;

    check_memory();
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
//            if (r->user() || (r->err & Hpt::ERR_U)) {
                Ec::current->disable_step_debug();
                current->launch_state = Ec::UNLAUNCHED;
                current->reset_counter();
                return;
//            }

        case Cpu::EXC_NM:
//            if (r->user() || (r->err & Hpt::ERR_U))
            check_memory();
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
        check_memory();
        send_msg<ret_user_iret>();
    }

    die("EXC", r);
}

void Ec::check_memory(mword from) {
    if ((Ec::current->is_idle()) || (Ec::current->cow_list == nullptr)) {
        current->run_number = 0;
        read_instCounter(); // just to zero counter
        current->launch_state = Ec::UNLAUNCHED;
        return;
    }
    //    if (!current->user_utcb) {
    //        Console::print(".....  Checking memory from %d. eip: %p", from, Ec::current->regs.REG(ip));
    //        current->ec_debug= true;
    //    }

    if (Ec::current->one_run_ok()) {
        current->exc_counter2 = Ec::exc_counter;
        current->counter2 = read_instCounter();
//        if(current->counter1 - current->counter2 - current->exc_counter1 + current->exc_counter2 != 0)
//            Console::print("Ec: %p  Pd: %p  X: %d | %d  A: %d | %d", current, current->pd.operator->(), current->counter1,  
//                    current->counter2, current->exc_counter1, current->exc_counter2);
        current->reset_counter();
        if (Ec::current->compare_and_commit()) {
            current->cow_list = nullptr;
            current->run_number = 0;
            current->launch_state = Ec::UNLAUNCHED;
            return;
        } else {
            Console::print("Checking failed");
            Ec::current->rollback();
            current->run_number = 0;
            current->cow_list = nullptr;
            switch (current->launch_state) {
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
        current->exc_counter1 = Ec::exc_counter;
        current->counter1 = read_instCounter();
        Ec::current->restore_state();
        current->run_number++;
        switch (current->launch_state) {
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

uint64 Ec::read_instCounter(){
   mword val = Msr::read<mword>(Msr::MSR_PERF_FIXED_CTR0); //no need to stop the counter because he is not supposed to count (according to config) when we are in kernl mode
   Msr::write (Msr::MSR_PERF_FIXED_CTR0, 0x0);
   Ec::exc_counter = 0;
   return val;
}

void Ec::reset_counter(){
    Ec::exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = 0;
    Msr::write (Msr::MSR_PERF_FIXED_CTR0, 0x0);
}