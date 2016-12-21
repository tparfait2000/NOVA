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
#include "utcb.hpp"
#include "lapic.hpp"

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
    Console::print("GP Here: Ec: %p  err: %08lx  addr: %08lx  eip: %08lx  val: %08x", current, r->err, r->cr2, eip, *(reinterpret_cast<uint32 *> (eip)));
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

    if (r->vec == 0xf)
        Console::print("Vec Heater: %lx", r->vec);
    switch (r->vec) {
        case Cpu::EXC_NMI:
            if (Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_STATUS) & 1ull << 32) {
                Console::print("PERF INTERRUPT OVERFLOW STATUS %llx  OVF_CTRL %llx", Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_STATUS), Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_OVF_CTRL));
                current->in_step_mode = true;
                current->regs.REG(fl) |= Cpu::EFL_TF;
                Console::print("STATUS %llx  OVF_CTRL %llx", Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_STATUS), Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_OVF_CTRL));
                return;
            }
            break;
        case Cpu::EXC_DB:
            if (current->in_step_mode) {
                compteur = current->nbInstr_to_execute;
                for (; compteur > 0;) {
                    Console::print("Step finished %u",compteur);
                    compteur--;
                    return;
                }
                compteur = 0;
                current->in_step_mode = false;
                check_memory(3001);
            }
            if (r->user()) {
                Ec::current->disable_step_debug();
                current->launch_state = Ec::UNLAUNCHED;
                current->reset_counter();
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
    //        Console::print(".....  Checking memory from %d ", pmi);
    //        //        current->ec_debug= true;
    //    }
    if (ec->one_run_ok()) {
        ec->exc_counter2 = Ec::exc_counter;
        ec->counter2 = readReset_instCounter();
        if (Ec::ec_debug) {
            Console::print("PMI: %d  Ec: %p  Pd: %p  X: %lld | %lld  A: %u | %u  gsi: %u | %u  lvt: %u | %u "
                    " msi: %u | %u  ipi: %u | %u", pmi, ec, pd, ec->counter1,
                    ec->counter2, ec->exc_counter1, ec->exc_counter2,
                    Ec::gsi_counter1, Ec::gsi_counter2, Ec::lvt_counter1, Ec::lvt_counter2,
                    Ec::msi_counter1, Ec::msi_counter2, Ec::ipi_counter1, Ec::ipi_counter2);
            Ec::ec_debug = false;
        }
        if (pmi == 3001) {
            Console::print("PMI: %d  counter2: %lld  exc: %d Run = 2  PMC0: %lld  EIP: %lx",
                    pmi, ec->counter2, ec->exc_counter2, Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip));
            //            Lapic::reset_pmi(ec->counter2 - ec->exc_counter2);
        }
        ec->reset_counter();

        if (pd->compare_and_commit()) {
            pd->cow_list = nullptr;
            ec->run_number = 0;
            ec->launch_state = Ec::UNLAUNCHED;
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
        ec->exc_counter1 = Ec::exc_counter;
        ec->counter1 = readReset_instCounter();
        if (pmi == 1251) {
            Console::print("PMI: %d  counter1: %lld  exc: %u Run = 1  PMC0: %lld  EIP: %lx",
                    pmi, ec->counter1, ec->exc_counter1, Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip));
            uint64 instruction_num = ec->counter1 - ec->exc_counter1; 
            if (instruction_num > step_nb){
                Lapic::reset_pmi(instruction_num - step_nb);
                ec->nbInstr_to_execute = step_nb;
            }else{
                ec->in_step_mode = true;
                ec->regs.REG(fl) |= Cpu::EFL_TF;
                ec->nbInstr_to_execute = instruction_num;
            }
        }
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


    return;
}

uint64 Ec::readReset_instCounter() {
    Ec::exc_counter = 0;
    uint64 val = Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0); //no need to stop the counter because he is not supposed to count (according to config) when we are in kernl mode
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, 0x0);
    return val;
}

void Ec::reset_counter() {
    Ec::exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = 0;
    Ec::gsi_counter1 = Ec::lvt_counter1 = Ec::msi_counter1 = Ec::ipi_counter1 =
            Ec::gsi_counter2 = Ec::lvt_counter2 = Ec::msi_counter2 = Ec::ipi_counter2 = 0;
    Lapic::reset_counter();
}