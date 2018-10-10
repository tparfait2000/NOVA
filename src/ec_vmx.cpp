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

#include "dmar.hpp"
#include "ec.hpp"
#include "gsi.hpp"
#include "lapic.hpp"
#include "vectors.hpp"
#include "vmx.hpp"
#include "vtlb.hpp"

void Ec::vmx_exception() {
    mword vect_info = Vmcs::read(Vmcs::IDT_VECT_INFO);

    if (vect_info & 0x80000000) {

        Vmcs::write(Vmcs::ENT_INTR_INFO, vect_info & ~0x1000);

        if (vect_info & 0x800)
            Vmcs::write(Vmcs::ENT_INTR_ERROR, Vmcs::read(Vmcs::IDT_VECT_ERROR));

        if ((vect_info >> 8 & 0x7) >= 4 && (vect_info >> 8 & 0x7) <= 6)
            Vmcs::write(Vmcs::ENT_INST_LEN, Vmcs::read(Vmcs::EXI_INST_LEN));
    };

    mword intr_info = Vmcs::read(Vmcs::EXI_INTR_INFO);

    switch (intr_info & 0x7ff) {

        default:
            current->regs.dst_portal = Vmcs::VMX_EXC_NMI;
            break;

        case 0x202: // NMI
            asm volatile ("int $0x2" : : : "memory");
            ret_user_vmresume();

        case 0x307: // #NM
            vm_check_memory(PES_DEV_NOT_AVAIL);
            handle_exc_nm();
            ret_user_vmresume();

        case 0x30e: // #PF
            //            vm_check_memory(5961);
            mword err = Vmcs::read(Vmcs::EXI_INTR_ERROR);
            mword cr2 = Vmcs::read(Vmcs::EXI_QUALIFICATION);

            switch (Vtlb::miss(&current->regs, cr2, err)) {
                case Vtlb::GPA_HPA:
                    current->regs.dst_portal = Vmcs::VMX_EPT_VIOLATION;
                    break;

                case Vtlb::GLA_GPA:
                    current->regs.cr2 = cr2;
                    Vmcs::write(Vmcs::ENT_INTR_INFO, intr_info & ~0x1000);
                    Vmcs::write(Vmcs::ENT_INTR_ERROR, err);

                case Vtlb::SUCCESS:
                    ret_user_vmresume();
            }
    }
    vm_check_memory(PES_VMX_SEND_MSG);

    send_msg<ret_user_vmresume>();
}

void Ec::vmx_extint() {
    unsigned vector = Vmcs::read(Vmcs::EXI_INTR_INFO) & 0xff;
    if(run_number == 0 && vector != VEC_LVT_PERFM){ //Non PMI external interrupt in 
        Lapic::eoi();
        vm_check_memory(PES_VMX_EXT_INT);
    }
    if (vector >= VEC_IPI)
        Lapic::ipi_vector(vector);
    else if (vector >= VEC_MSI)
        Dmar::vector(vector);
    else if (vector >= VEC_LVT){
        Lapic::lvt_vector(vector);
    } else if (vector >= VEC_GSI)
        Gsi::vector(vector);

    ret_user_vmresume();
}

void Ec::vmx_invlpg() {
    current->regs.tlb_flush<Vmcs>(Vmcs::read(Vmcs::EXI_QUALIFICATION));
    Vmcs::adjust_rip();
    ret_user_vmresume();
}

void Ec::enable_rdtsc() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val &= ~Vmcs::CPU_RDTSC;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::disable_rdtsc() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val |= Vmcs::CPU_RDTSC;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::enable_mtf() {
    if (!Vmcs::has_mtf()) return;
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val |= Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::disable_mtf() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val &= ~Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::emulate_rdtsc() {
    mword h = 0, l = 0, aux = 0;
    mword inst_addr = Vmcs::read(Vmcs::GUEST_RIP);
    mword inst_off = inst_addr & PAGE_MASK;
    uint64 entry = 0;
    if (!current->regs.vtlb->vtlb_lookup(inst_addr)) {
        Console::print("Instr_addr not found %lx", inst_addr);
    }
    uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::current->quota, entry & ~PAGE_MASK));  
    uint16 *inst_val = reinterpret_cast<uint16 *>(ptr + inst_off);
    mword off = 0, off_hi = 0, mul = 0, mul_hi = 0;
    bool is_tsc_scale_defined = Vmcs::read(Vmcs::CPU_EXEC_CTRL1) & Vmcs::CPU_TSC_MUL;
    mul = is_tsc_scale_defined ? Vmcs::read(Vmcs::TSC_MUL) : 1;
    mul_hi = is_tsc_scale_defined ? Vmcs::read(Vmcs::TSC_MUL_HI) : 1;

    switch(*inst_val){
        case 0x310f:
            asm volatile ("rdtsc" : "=a" (l), "=d" (h));
            break;
        case 0xf901:
            asm volatile ("rdtscp" : "=a" (l), "=d" (h), "=c" (aux));
            current->regs.REG(cx) = off + aux*mul;            
            break;
        default:
            Console::print("Instr_val not found inst_addr %lx entry %llx ptr %p inst_off %lx inst_val %x", inst_addr, entry, ptr, inst_off, *inst_val);
    }        

    if (Vmcs::read(Vmcs::CPU_EXEC_CTRL0) & Vmcs::CPU_TSC_OFFSET) {
        off = Vmcs::read(Vmcs::TSC_OFFSET);
        off_hi = Vmcs::read(Vmcs::TSC_OFFSET_HI);
    }

    mword delta_tsc = (tsc2 - tsc1)/2;
    current->regs.REG(ax) = off + l*mul + (delta_tsc & 0xffffffff); //Consider using current->regs.vmx_write_gpr(gpr, regs_number) if there is a problem;
    current->regs.REG(dx) = off_hi + h*mul_hi + (delta_tsc >> 32);
    
//    Console::print("rdtsc tsc1 %lu tsc2 %lu delta %lu ax %lu dx %lu", tscm1, tscm2, tscm2 - tscm1, current->regs.REG(ax), current->regs.REG(dx));
    current->regs.vmcs->adjust_rip();
}

void Ec::emulate_rdtsc2() {
    mword tsc = (tsc1 + tsc2)/2;
    current->regs.REG(ax) = tsc & 0xffffffff;
    current->regs.REG(dx) = tsc >> 32;
//    Console::print("rdtsc tsc1 %llu tsc2 %llu delta %llu ax %lu dx %lu", tsc1, tsc2, tsc2 - tsc1, current->regs.REG(ax), current->regs.REG(dx));
    current->regs.vmcs->adjust_rip();
}

void Ec::enable_single_step() {
    enable_mtf();
    enable_rdtsc();
//    ec_debug = true;
    step_reason = SR_RDTSC;
    current->regs.vmcs->make_current();
}

void Ec::disable_single_step() {
    disable_mtf();
    disable_rdtsc();
    step_reason = SR_NIL;
    ret_user_vmresume();
}

void Ec::resolve_rdtsc() {
    if (Vmcs::has_mtf()) // if the CPU honors the monitor trap flag
        enable_single_step();
    else
        emulate_rdtsc();
    ret_user_vmresume();
}

void Ec::resolve_rdtscp() {
    Console::print("RDTSCP resolving, Todo...");
    ret_user_vmresume();    
}

void Ec::vmx_enable_single_step(){
    enable_mtf();
//    ec_debug = true;
    step_reason = SR_PMI;
    current->regs.vmcs->make_current();
}

void Ec::vmx_disable_single_step() {
    mword current_rip = Vmcs::read(Vmcs::GUEST_RIP);
    mword inst_off = current_rip & PAGE_MASK;
    uint64 entry = 0;
    if (!current->regs.vtlb->vtlb_lookup(current_rip)) {
        Console::print("Instr_addr not found %lx", current_rip);
    }
    uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::current->quota, entry & ~PAGE_MASK));  
    mword *inst_val = reinterpret_cast<mword *>(ptr + inst_off);
    Console::print("nbInstr_to_execute %lld current_rip %lx current_rax %lx current_rcx %lx inst %lx", 
            nbInstr_to_execute, current_rip, current->regs.REG(ax), current->regs.REG(cx), *inst_val);
    if (prev_rip == current_rip) {
        // It may happen that this is the final instruction
        if ((current_rip == end_rip) && (current->regs.REG(cx) == end_rcx)) {
            disable_mtf();
            step_reason = SR_NIL;
            vm_check_memory(PES_PMI);
        }
    } else {
        if (nbInstr_to_execute > 0)
            nbInstr_to_execute--;
    }
    prev_rip = current_rip;
    if (nbInstr_to_execute > 0) {
        ret_user_vmresume();
    }
    if ((current_rip == end_rip) && (current->regs.REG(cx) == end_rcx)) {
            disable_mtf();
            step_reason = SR_NIL;
            vm_check_memory(PES_PMI);
    } else {
        nbInstr_to_execute = 1;
        ret_user_vmresume();
    }
    ret_user_vmresume();
}

void Ec::vmx_cr() {
    mword qual = Vmcs::read(Vmcs::EXI_QUALIFICATION);

    unsigned gpr = qual >> 8 & 0xf;
    unsigned acc = qual >> 4 & 0x3;
    unsigned cr = qual & 0xf;

    switch (acc) {
        case 0: // MOV to CR
        {
            if (cr == 8) {
                /* Let the VMM handle CR8 */
                current->regs.dst_portal = Vmcs::VMX_CR;
                send_msg<ret_user_vmresume>();
            }

            mword old_cr0 = current->regs.read_cr<Vmcs>(0);
            mword old_cr4 = current->regs.read_cr<Vmcs>(4);

            current->regs.write_cr<Vmcs> (cr, current->regs.vmx_read_gpr(gpr));

            /*
             * Let the VMM update the PDPTE registers if necessary.
             *
             * Intel manual sections 4.4.1 of Vol. 3A and 26.3.2.4 of Vol. 3C
             * indicate the conditions when this is the case.
             */

            /* no update needed if nested paging is not enabled */
            if (!current->regs.nst_on)
                break;

            mword cr0 = current->regs.read_cr<Vmcs>(0);
            mword cr4 = current->regs.read_cr<Vmcs>(4);

            /* no update needed if not in protected mode with paging and PAE enabled */
            if (!((cr0 & Cpu::CR0_PE) &&
                    (cr0 & Cpu::CR0_PG) &&
                    (cr4 & Cpu::CR4_PAE)))
                break;

            /* no update needed if no relevant bits of CR0 or CR4 have changed */
            if ((cr != 3) &&
                    ((cr0 & Cpu::CR0_CD) == (old_cr0 & Cpu::CR0_CD)) &&
                    ((cr0 & Cpu::CR0_NW) == (old_cr0 & Cpu::CR0_NW)) &&
                    ((cr0 & Cpu::CR0_PG) == (old_cr0 & Cpu::CR0_PG)) &&
                    ((cr4 & Cpu::CR4_PAE) == (old_cr4 & Cpu::CR4_PAE)) &&
                    ((cr4 & Cpu::CR4_PGE) == (old_cr4 & Cpu::CR4_PGE)) &&
                    ((cr4 & Cpu::CR4_PSE) == (old_cr4 & Cpu::CR4_PSE)) &&
                    ((cr4 & Cpu::CR4_SMEP) == (old_cr4 & Cpu::CR4_SMEP)))
                break;

            /* PDPTE register update necessary */
            current->regs.dst_portal = Vmcs::VMX_CR;
            send_msg<ret_user_vmresume>();

            break;
        }
        case 1: // MOV from CR

            if (cr == 8) {
                /* Let the VMM handle CR8 */
                current->regs.dst_portal = Vmcs::VMX_CR;
                send_msg<ret_user_vmresume>();
            }

            assert(cr != 0 && cr != 4);
            current->regs.vmx_write_gpr(gpr, current->regs.read_cr<Vmcs> (cr));
            break;
        case 2: // CLTS
            current->regs.write_cr<Vmcs> (cr, current->regs.read_cr<Vmcs> (cr) & ~Cpu::CR0_TS);
            break;
        default:
            UNREACHED;
    }

    Vmcs::adjust_rip();
    ret_user_vmresume();
}

void Ec::handle_vmx() {
    Cpu::hazard = (Cpu::hazard | HZD_DS_ES | HZD_TR) & ~HZD_FPU;

    mword reason = Vmcs::read(Vmcs::EXI_REASON) & 0xff;
    Lapic::write_perf(reason);
    Counter::vmi[reason]++;
//    Console::print("VM Exit %08lx VMRip %lx VMcx %lx counter %llx", reason, Vmcs::read(Vmcs::GUEST_RIP), current->regs.REG(cx), Lapic::counter);
    if(Lapic::tour >= 66600)
        Console::print("VmExit tour %u RIP %lx reason %lu", Lapic::tour, Vmcs::read(Vmcs::GUEST_RIP), reason);

    switch (reason) {
        case Vmcs::VMX_EXC_NMI: vmx_exception();
        case Vmcs::VMX_EXTINT: vmx_extint();
        case Vmcs::VMX_INVLPG:
        {
            vm_check_memory(5965);
            vmx_invlpg();
        }
        case Vmcs::VMX_RDTSC:
            if(run_number == 0)
                tsc1 = rdtsc();
            vm_check_memory(5968);
            tsc2 = rdtsc();
            resolve_rdtsc();
        case Vmcs::VMX_CR:
        {
            vm_check_memory(5966);
            vmx_cr();
        }
        case Vmcs::VMX_MTF:
            switch(step_reason){
                case SR_RDTSC:
                    disable_single_step();
                case SR_PMI:
                    vmx_disable_single_step();
            }
        case Vmcs::VMX_EPT_VIOLATION:
            vm_check_memory(5967);
            current->regs.nst_error = Vmcs::read(Vmcs::EXI_QUALIFICATION);
            current->regs.nst_fault = Vmcs::read(Vmcs::INFO_PHYS_ADDR);
            break;
        case Vmcs::VMX_RDTSCP:
            vm_check_memory(5969);
            Console::print("RDTSCP in VM");
            resolve_rdtscp();
            break;
    }

    //TODO : VMX_IO single stepping
    vm_check_memory(5970);
    current->regs.dst_portal = reason;

    send_msg<ret_user_vmresume>();
}

void Ec::vm_check_memory(int reason) {
    Ec *ec = current;
    Pd *pd = ec->getPd();
//    if (is_idle())
//        Console::print("TCHA HOHO Must not be idle here, sth wrong. pmi: %d cowlist: %p Pd: %s", pmi, current->getPd()->cow_list, current->getPd()->get_name());
    if (!pd->cow_list) {
        launch_state = UNLAUNCHED;
        reset_all();
        return;
    }
    
    switch (run_number){
        case 0:
            exc_counter1 = exc_counter;
            exc_counter = 0;
            end_rip = last_rip;
            end_rcx = last_rcx;
            counter1 = Lapic::nb_executed_instr();
            prev_reason = reason;
            run_number++;
            ec->vmx_restore_state();
            Console::print("reason %d utcb %p counter1 %llu counter 0x%llx exc1 %llu diff %ld tour %u GuestIP %lx", 
                    reason, ec->utcb, counter1, Lapic::counter, exc_counter1, static_cast<long> (counter1 - exc_counter1), Lapic::tour, last_rip);            
            Lapic::compute_expected_info(static_cast<uint32>(exc_counter1), reason);
            switch(reason){
                case PES_SINGLE_STEP: //Perf Monitoring Interrupt
                    Lapic::program_pmi2(MAX_INSTRUCTION);
                    break;
                case PES_VMX_EXT_INT: // vmx external interrupt
                    if(counter1 == 0){ //No instruction was executed
                        launch_state = UNLAUNCHED;
                        reset_all();
                        return;    
                    }
                    ec->run1_ext_int_check(reason);
                    break;
                default:
                    Lapic::cancel_pmi();
            }
            check_exit();
            break;
        case 1:{
            if (reason == 3002) {
                ec->run2_pmi_check(reason);            
            }
            int regs_not_ok = ec->compare_regs(reason);
            bool cc = false;
            if (regs_not_ok) {
                Console::print("REGS does not match pmi %d utcb %p reason: %d Pd %s Ec %s", reason, ec->utcb, regs_not_ok, ec->getPd()->get_name(), ec->get_name());
                cc = true;
            }
            cc |= pd->vtlb_compare_and_commit();
            if (cc) {
                Console::print("Checking failed Ec: %p utcb %p PMI: %d Pd: %s launch_state: %d", ec, ec->utcb, reason, pd->get_name(), launch_state);
                Console::print("eip0: %lx  rcx0: %lx  r11_0: %lx  rdi_0: %lx", regs_0.REG(ip), regs_0.REG(cx), regs_0.r11, regs_0.REG(di));
                Console::print("eip1: %lx  rcx1: %lx  r11_1: %lx  rdi_1: %lx", regs_1.REG(ip), regs_1.REG(cx), regs_1.r11, regs_1.REG(di));
                Console::print("eip: %lx  rcx: %lx  r11: %lx  rdi: %lx", ec->regs.REG(ip), ec->regs.REG(cx), ec->regs.r11, ec->regs.REG(di));
                Lapic::print_compteur();
                ec->rollback();
                ec->reset_all();
                check_exit();
            } else {
                launch_state = UNLAUNCHED;
                reset_all();
                return;
            }
            break;}
        default:
            Console::print("Weird run_number %d", run_number);
            die("Weird run_number");
    }
    return;
}

void Ec::run1_ext_int_check(int reason){ 
    if (static_cast<long> (step_nb) > static_cast<long> (counter1)){
        Console::print("reason %d step_nb too small utcb %p counter1 %llu exc1 %llu diff %ld start_rip %lx start_rcx %lx end_rip %lx end_rcx %lx", 
                reason, utcb, counter1, exc_counter1, static_cast<long> (counter1 - exc_counter1), Vmcs::read(Vmcs::GUEST_RIP), regs.REG(cx), end_rip, end_rcx);
        exc_counter = 0;
        if(Vmcs::has_mtf()){
            nbInstr_to_execute = counter1;
            prev_rip = Vmcs::read(Vmcs::GUEST_RIP);                    
            vmx_enable_single_step();
            ret_user_vmresume();
        } else {
            Lapic::program_pmi2(counter1);
        }
    }else{
        Lapic::program_pmi2(counter1);   
    } 
    exc_counter = 0;
}

void Ec::run2_pmi_check(int reason){
    if (reason != prev_reason){
            //means that reason was simultaneous to another exception, which has been prioritized. 
            //And the PMI is now to be serviced; but it does not matter anymore. Just launch the 2nd run.
        if(prev_reason != 5972){
            Console::print("reason different from previous_reason utcb %p previous_reason %d reason %d", utcb, prev_reason, reason);
            check_exit();
        }
    }
    exc_counter2 = exc_counter;
    counter2 = Lapic::nb_executed_instr();
    if(Vmcs::has_mtf()){
        if(counter1 > counter2){
            nbInstr_to_execute = counter1 - counter2;  
            Console::print("PMI inf utcb %p counter1 %llu exc1 %llu counter2 %llu exc2 %llu last_rip %lx last_rcx %lx endrip %lx endrcx %lx", utcb, counter1, exc_counter1, counter2, exc_counter2, last_rip, last_rcx, end_rip, end_rcx);
            prev_rip = Vmcs::read(Vmcs::GUEST_RIP);                    
            vmx_enable_single_step();
            ret_user_vmresume();
        } else if(counter1 < counter2){
            nbInstr_to_execute = counter2 - counter1;  
            Console::print("PMI sup utcb %p counter1 %llu exc1 %llu counter2 %llu exc2 %llu last_rip %lx last_rcx %lx endrip1 %lx endrcx1 %lx endrip2 %lx endrcx2 %lx", 
                    utcb, counter1, exc_counter1, counter2, exc_counter2, last_rip, last_rcx, end_rip, end_rcx, Vmcs::read(Vmcs::GUEST_RIP), current->get_regsRCX());
            end_rip = Vmcs::read(Vmcs::GUEST_RIP);
            end_rcx = current->get_regsRCX();
            current->vmx_restore_state1();
            prev_rip = Vmcs::read(Vmcs::GUEST_RIP);                    
            vmx_enable_single_step();
            ret_user_vmresume();
        } else {
            Console::print("PMI equal utcb %p counter1 %llu exc1 %llu counter2 %llu exc2 %llu last_rip %lx last_rcx %lx endrip %lx endrcx %lx", utcb, counter1, exc_counter1, counter2, exc_counter2, last_rip, last_rcx, end_rip, end_rcx);
            if ((last_rip != end_rip) || (last_rcx != end_rcx)) {
                Console::print("No match last_rip %lx last rcx %lx", last_rip, last_rcx);
                rollback();
                reset_all();
                check_exit();
            }
        }
    } else {
        if ((last_rip != end_rip) || (last_rcx != end_rcx)) {// This should never happen since Simics is very accurate
            Console::print("PMI Diff with no MTF for Single stepping utcb %p counter1 %llu exc1 %llu counter2 %llu exc2 %llu"
            "last_rip %lx end_rip %lx last_rcx %lx end_rcx %lx", utcb, counter1, exc_counter1, counter2, exc_counter2, last_rip, end_rip, last_rcx, end_rcx);
            rollback();
            reset_all();
            nb_try++;
            check_exit();
        }else{
            Console::print("PMI OK utcb %p", utcb);
            nb_try = 0;
        }
    }
}
