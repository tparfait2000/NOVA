/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2013-2018 Alexander Boettcher, Genode Labs GmbH.
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
#include "vmx.hpp"
#include "gsi.hpp"
#include "Pending_int.hpp"

void Ec::load_fpu()
{
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl (true);

    if (EXPECT_FALSE (!fpu)) {
        if (Cmdline::fpu_eager && !utcb)
            regs.fpu_ctrl (true);

        Fpu::init();
    }
    else
        fpu->load();
}

void Ec::save_fpu()
{
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl (false);

    if (EXPECT_FALSE(!fpu))
        fpu = new (pd->quota) Fpu;

    fpu->save();
}

void Ec::transfer_fpu (Ec *ec)
{
    assert(!idle_ec());

    if (!(Cpu::hazard & HZD_FPU)) {

        Fpu::enable();

        if (fpowner != this) {
            if (fpowner)
                fpowner->save_fpu();
            load_fpu();
        }
    }

    if (fpowner && fpowner->del_rcu()) {
        Ec * last = fpowner;
        fpowner = nullptr;
        Rcu::call (last);
    }

    fpowner = ec;
    bool ok = fpowner->add_ref();
    assert (ok);
}

void Ec::handle_exc_nm()
{
    if (Cmdline::fpu_eager)
        die ("FPU fault");

    Fpu::enable();

    if (current == fpowner) {
        if (!current->utcb && !current->regs.fpu_on)
           current->regs.fpu_ctrl (true);
        return;
    }

    if (fpowner)
        fpowner->save_fpu();

    current->load_fpu();

    if (fpowner && fpowner->del_rcu()) {
        Ec * last = fpowner;
        fpowner = nullptr;
        Rcu::call (last);
    }

    fpowner = current;
    bool ok = fpowner->add_ref();
    assert (ok);
}

bool Ec::handle_exc_ts(Exc_regs *r) {
    if (r->user()) {
        check_memory(PES_INVALID_TSS);
        return false;
    }
    // SYSENTER with EFLAGS.NT=1 and IRET faulted
    r->REG(fl) &= ~Cpu::EFL_NT;

    return true;
}

bool Ec::handle_exc_gp(Exc_regs *r) {
    mword eip = r->REG(ip);
    if (r->user())
        check_memory(PES_GP_FAULT);
    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }

    if (fixup (r->REG(ip))) {
            r->REG(ax) = r->cr2;
            return true;
    }
    Ec* ec = current;
    if (r->user()){
        if (ec->is_temporal_exc()) {
            ec->enable_step_debug(SR_RDTSC);
            return true;
        } else if (ec->is_io_exc()) {
            if(is_rep_prefix_io_exception(eip)){
//                Console::print("REP IN PIO");                
                set_io_state(SR_PIO);
            } else {
                ec->resolve_PIO_execption();                
            }
            return true;
        }
    }
   
    Console::print("eip0: %lx(%#lx)  r11_0: %lx", regs_0.REG(ip), regs_0.REG(cx), regs_0.r11);
    Console::print("eip1: %lx(%#lx)  r11_1: %lx", regs_1.REG(ip), regs_1.REG(cx), regs_1.r11);
    Console::print("eip2: %lx(%#lx)  r11_2: %lx", regs_2.REG(ip), regs_2.REG(cx), regs_2.r11);
    char buff[MAX_STR_LENGTH];
    instruction_in_hex(*(reinterpret_cast<mword *> (eip)), buff);
    Console::print("GP Here: Ec: %s  Pd: %s ip %lx(%#lx) val: %s Lapic::counter %llx user %s", 
        ec->get_name(), ec->getPd()->get_name(), eip, r->ARG_IP, buff, Lapic::read_instCounter(), r->user() ? "true" : "false");
    Counter::dump();
    ec->start_debugging(Debug_type::STORE_RUN_STATE);
    if(!ec->utcb){
        mword inst_addr = Vmcs::read(Vmcs::GUEST_RIP);
        mword inst_off = inst_addr & PAGE_MASK;
        uint64 entry = 0;
        if (!current->regs.vtlb_lookup(inst_addr, entry)) {
            Console::print("Instr_addr not found %lx", inst_addr);
        }
        uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, entry & ~PAGE_MASK));  
        uint64 *inst_val = reinterpret_cast<uint64 *>(ptr + inst_off);
        Console::print("VMip: %lx VMcx %lx val %llx", inst_addr, ec->regs.REG(cx), *inst_val);        
    }
    return false;
}

bool Ec::handle_exc_pf(Exc_regs *r) {
    mword addr = r->cr2;

    //    if(((addr & ~PAGE_MASK) >= 0x9800000) && ((addr & ~PAGE_MASK) <= 0x9a00000))
    //        Console::print("addr 0x9800000");
    if ((r->err & Hpt::ERR_U) && Pd::current->Space_mem::loc[Cpu::id].is_cow_fault(Pd::current->quota, addr, r->err))
        return true;
    if (r->cs & 3)
        check_memory(PES_PAGE_FAULT);

    if (r->err & Hpt::ERR_U)
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR, r->err);

    if (addr < USER_ADDR) {

        if (Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR, r->err))
            return true;

        if (fixup(r->REG(ip))) {
            r->REG(ax) = addr;
            return true;
        }
    }

    if (addr >= LINK_ADDR && addr < CPU_LOCAL && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Hptp(reinterpret_cast<mword> (&PDBR)), addr, CPU_LOCAL, r->err))
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
            if (get_dr6() & 0x1) { // debug register 0
                Console::print("Debug register 0 Ec %s Pd %s eip %lx", current->get_name(), current->getPd()->get_name(), current->regs.REG(ip));
                mword *p = reinterpret_cast<mword*> (0x18028);
                Paddr physical_addr;
                mword attribut;
                size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
                if (is_mapped)
                    Console::print("Debug breakpoint at value phys %lx 18028:%lx", physical_addr, *p);
                return;
            }
            if (r->user()) {
                switch (step_reason) {
                    case SR_MMIO:
                    case SR_PIO:
                    case SR_RDTSC:
                        //                        Console::print("EXC_DB step_reason: %d", step_reason);
                        if (not_nul_cowlist && step_reason != SR_PIO) {
                            Console::print("cow_list not null was noticed Pd: %s", current->getPd()->get_name());
                            not_nul_cowlist = false;
                        }
                        if (current->getPd()->cow_list) {
                            if (step_reason != SR_PIO)
                                Console::print("cow_list not null, noticed! Pd: %s", current->getPd()->get_name());
                            else {
                                not_nul_cowlist = true;
                            }
                        }
                        current->disable_step_debug();
                        launch_state = UNLAUNCHED;
                        reset_all();
                        return;
                    case SR_PMI:{
                        nb_inst_single_step++;
                        if (nbInstr_to_execute > 0)
                            nbInstr_to_execute--;
                        if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                            nb_inst_single_step--;
                            nbInstr_to_execute++;           // Re-adjust the number of instruction                  
                            // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                            // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                            // It may happen that this is the final instruction
                            if (!current->compare_regs_mute()) {
//                                check_instr_number_equals(1);
                                current->disable_step_debug();
                                check_memory(PES_SINGLE_STEP);
                                return;
                            }
                        }
                        prev_rip = current->regs.REG(ip);
                        // No need to compare if nbInstr_to_execute > 3 
                        if (nbInstr_to_execute > 3) {
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                            return;
                        }
                        if (!current->compare_regs_mute()) {
//                            check_instr_number_equals(2);
                            current->disable_step_debug();
                            check_memory(PES_SINGLE_STEP);
                            return;
                        } else {
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                            nbInstr_to_execute = 1;
                            return;
                        }
                        break;}
                    case SR_GP:
                        return;
                        break;
                    case SR_DBG:
                        if (nbInstr_to_execute > 0) {
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                            debug_record_info();
                            nbInstr_to_execute --;
                            single_step_number ++;
                            return;
                        } else {
                            if(run_number == 0){
                                Console::print("Relaunching for the second run");
                                current->restore_state();
                                nbInstr_to_execute = MAX_INSTRUCTION + counter2 - exc_counter2;
                                run_number++;
                                check_exit();
                            } else{
                                Console::panic("Finish");
                            }
                        }
                        break;
                    case SR_EQU:
                        nb_inst_single_step++;
                        if (nbInstr_to_execute > 0)
                            nbInstr_to_execute--;
                        if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                            nb_inst_single_step--;
                            nbInstr_to_execute++;           // Re-adjust the number of instruction                  
                            // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                            // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                            // It may happen that this is the final instruction
                            if (!current->compare_regs_mute()) {
//                                check_instr_number_equals(3);
                                current->disable_step_debug();
                                check_memory(PES_SINGLE_STEP);
                                return;
                            }
                        }
                        //here, single stepping 2nd run should be ok
                        if (!current->compare_regs_mute()) {// if ok?
//                            check_instr_number_equals(4);
                            current->disable_step_debug();
                            check_memory(PES_SINGLE_STEP);
                            return;
                        } else { 
                            if(nbInstr_to_execute == 0){ // single stepping the first run with 2 credits instructions
                                current->restore_state1();
                                nbInstr_to_execute = distance_instruction + nb_inst_single_step + 1;
                                nb_inst_single_step = 0;
                                first_run_advanced = true;
                                current->regs.REG(fl) |= Cpu::EFL_TF;
                                return;
                            } else { // relaunch the first run without restoring the second execution state
                                current->regs.REG(fl) |= Cpu::EFL_TF;
                                return;                                
                            }
                        }
                        break;
                    default:
                        Console::print("No step Reason");
                        die("No step Reason");
                }
            } else {
                Console::print("Debug in kernel Step Reason %d  nbInstr_to_execute %llu  debug_compteur %llu  end_rip %lx  end_rcx %lx", step_reason, nbInstr_to_execute, debug_compteur, end_rip, end_rcx);
                break;
            }
        
        case Cpu::EXC_NMI:
//            Console::print("PMI occured on NMI counter %llx reg %x", Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), 
//                   Lapic::read_perf_reg());
//            Lapic::program_pmi();
//            Console::print("reg %x", Lapic::read_perf_reg());
            return;
        case Cpu::EXC_BP:{
            current->regs.REG(ip)--; // adjust EIP to EIP -   after the trap;
            mword eip = current->regs.REG(ip);
            Paddr p; mword a;
            current->pd->Space_mem::loc[Cpu::id].lookup(eip & ~PAGE_MASK, p, a);
            if(!(a & Hpt::HPT_W))
                current->pd->Space_mem::loc[Cpu::id].replace_cow(Pd::current->quota, eip, p | a | Hpt::HPT_W);
            *(reinterpret_cast<uint8*>(eip)) = replaced_int3_instruction;
            if(!(a & Hpt::HPT_W))
                Pd::current->Space_mem::loc[Cpu::id].replace_cow(Pd::current->quota, eip, p | a);
            reset_io_state();
            current->pd->Space_mem::loc[Cpu::id].lookup(eip & ~PAGE_MASK, p, a);
            return;}
        case Cpu::EXC_NM:
            if (r->user())
                check_memory(PES_DEV_NOT_AVAIL);
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

        case Cpu::EXC_AC:
            Console::print("Alignement check exception");

        case Cpu::EXC_MC:
            Mca::vector();
            break;
    }

    if (r->user()) {
        if (!is_idle() || current->getPd()->cow_list)
            check_memory(PES_SEND_MSG);
        send_msg<ret_user_iret>();
    }

    die("EXC", r);
}

void Ec::check_memory(PE_stopby from) {
    Ec *ec = current;
    Pd *pd = ec->getPd();
//    if (is_idle())
//        Console::print("TCHA HOHO Must not be idle here, sth wrong. pmi: %d cowlist: %p Pd: %s", pmi, current->getPd()->cow_list, current->getPd()->get_name());
    if (!pd->cow_list) {
        launch_state = UNLAUNCHED;
        reset_all();
        return;
    }

//  Console::print("EIP = check_memory utcb %p run %d pmi %d counter %llx exc %lld rcx %lx eip %lx", ec->utcb, run_number, pmi, Lapic::read_instCounter(), exc_counter, current->regs.REG(cx), current->regs.REG(ip));
    switch(run_number){
        case 0:
            ec->restore_state();
            if (from == PES_PMI || from == PES_GSI || from == PES_MSI || from == PES_MSI) {
                prev_reason = from;
                end_rip = last_rip;
                end_rcx = last_rcx;
                exc_counter1 = exc_counter;
                double_interrupt_counter1 = double_interrupt_counter;
                msi_counter1 = msi_counter;
                gsi_counter1 = gsi_counter;
                lvt_counter1 = lvt_counter;
                pf_counter1 = pf_counter;
                exc_no_pf_counter1 = exc_no_pf_counter;
                ipi_counter1 = ipi_counter;
                rep_counter1 = rep_counter;
                hlt_counter1 = hlt_counter;
                counter1 = Lapic::read_instCounter();
                first_run_instr_number = MAX_INSTRUCTION + counter1 - exc_counter1;
                Lapic::program_pmi(MAX_INSTRUCTION);
            } else {
                Lapic::cancel_pmi();
            }
            run_number++;
            exc_counter = 0;
            double_interrupt_counter = msi_counter = gsi_counter = lvt_counter = pf_counter = exc_no_pf_counter = ipi_counter = rep_counter = hlt_counter = 0;
            check_exit();
            break;
        case 1:
            if (from == PES_PMI || from == PES_GSI || from == PES_MSI || from == PES_LVT) {
                if(from != prev_reason && prev_reason != PES_GSI && prev_reason != PES_MSI && prev_reason != PES_LVT){
                    //means that pmi was simultaneous to another exception, which has been prioritized. 
                    //And the PMI is now to be serviced; but it does not matter anymore. Just launch the 2nd run.
                    Console::print("from %d different from previous_reason %d", from, prev_reason);
                    check_exit();
                }
                exc_counter2 = exc_counter;
                double_interrupt_counter2 = double_interrupt_counter;
                msi_counter2 = msi_counter;
                gsi_counter2 = gsi_counter;
                lvt_counter2 = lvt_counter;
                pf_counter2 = pf_counter;
                exc_no_pf_counter2 = exc_no_pf_counter;
                ipi_counter2 = ipi_counter;
                rep_counter2 = rep_counter;
                hlt_counter2 = hlt_counter;
                counter2 = Lapic::read_instCounter();
                second_run_instr_number = MAX_INSTRUCTION + counter2 - exc_counter2;
                distance_instruction = distance(first_run_instr_number, second_run_instr_number);
                if(distance_instruction <=2){
                    if (ec->compare_regs_mute()) {
                        nbInstr_to_execute = distance_instruction + 1;
                        prev_rip = current->regs.REG(ip);
                        ec->enable_step_debug(SR_EQU);
                        ret_user_iret();   
                    }else{
//                        check_instr_number_equals(5);                        
                    }
                } else if (first_run_instr_number > second_run_instr_number) {
                    nbInstr_to_execute = first_run_instr_number - second_run_instr_number;
                    prev_rip = current->regs.REG(ip);
                    ec->enable_step_debug(SR_PMI);
                    ret_user_iret();
                } else if (first_run_instr_number < second_run_instr_number) {
                    ec->restore_state1();
                    nbInstr_to_execute = second_run_instr_number - first_run_instr_number;
                    prev_rip = current->regs.REG(ip);
                    ec->enable_step_debug(SR_PMI);
                    ret_user_iret();
                }
            }
            {
                ec->regs_2 = ec->regs;
                reg_diff = ec->compare_regs(from);
                if (reg_diff || pd->compare_and_commit()) {
                    Console::print("Checking failed : Ec %s  Pd: %s From: %d launch_state: %d", ec->get_name(), pd->get_name(), from, launch_state);
                    ec->rollback();
    //                ec->reset_all();
    //                check_exit();
                    current->pd->cow_list = nullptr;
                    run_number = 0;
                    nbInstr_to_execute = first_run_instr_number;
                    current->save_state();
                    launch_state = Ec::IRET;
                    current->enable_step_debug(SR_DBG);
                    check_exit();
                } else {
                    launch_state = UNLAUNCHED;
                    reset_all();
                    return;
                }
            }
        default:
            Console::panic("run_number must be 0 or 1. Current run_number is %d", run_number);
    }
}

void Ec::check_exit() {
    switch (launch_state) {
        case SYSEXIT:
            ret_user_sysexit();
            break;
        case IRET:
            ret_user_iret();
            break;
        case VMRESUME:
            ret_user_vmresume();
            break;
        case VMRUN:
            ret_user_vmrun();
            break;
        case UNLAUNCHED:
            Console::panic("Bad Run launch_state %u", launch_state);
    }
}

void Ec::reset_counter() {
    exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = double_interrupt_counter = counter_userspace = 0;
    gsi_counter1 = lvt_counter1 = msi_counter1 = ipi_counter1 = gsi_counter2 = 
            lvt_counter2 = msi_counter2 = ipi_counter2 = nb_inst_single_step = 0 ; 
    ipi_counter = msi_counter = gsi_counter = lvt_counter = exc_no_pf_counter = exc_no_pf_counter1 = 
    exc_no_pf_counter2 = pf_counter = pf_counter1 = pf_counter2 = rep_counter1 = rep_counter = rep_counter2 =
    hlt_counter = hlt_counter1 = hlt_counter2 = distance_instruction = 0;
    Lapic::program_pmi();
}

void Ec::reset_all() {
    current->pd->cow_list = nullptr;
    run_number = 0;
    reset_counter();
    prev_reason = 0;
    no_further_check = false;
    Pending_int::exec_pending_interrupt();
    current->free_recorded_pe();
}

void Ec::start_debugging(Debug_type dt){
    debug_type = dt;
    rollback();
//                ec->reset_all();
//                check_exit();
    pd->cow_list = nullptr;
    run_number = 0;
    nbInstr_to_execute = first_run_instr_number;
    save_state();
    launch_state = Ec::IRET;
    enable_step_debug(SR_DBG);
    check_exit();
}

void Ec::debug_record_info(){
    switch(debug_type){
        case CMP_TWO_RUN:
            switch (run_number){
                case 0:
                    outpout_table0[single_step_number][0] = current->regs.REG(ip);
                    outpout_table0[single_step_number][1] = current->get_reg(reg_diff);
                    break;
                case 1:
                    outpout_table1[single_step_number][0] = current->regs.REG(ip);
                    outpout_table1[single_step_number][1] = current->get_reg(reg_diff);
                    if(outpout_table0[single_step_number][0] != outpout_table1[single_step_number][0] ||
                            outpout_table0[single_step_number][1] != outpout_table1[single_step_number][1])
                        Console::print("Single_step_number %llu RIP %lx %lx %s %lx %lx", single_step_number, outpout_table0[single_step_number][0], 
                                outpout_table1[single_step_number][0], regs_name_table[reg_diff], outpout_table0[single_step_number][1], outpout_table1[single_step_number][1]);
                    break;
                default:
                    Console::panic("run_number odd");  
            }
            break;
        case STORE_RUN_STATE:
            current->take_snaphot();
            break;
        default:
            Console::panic("Undefined debug type %u", debug_type);
    }
}