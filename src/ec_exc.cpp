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
#include "vmx.hpp"

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
    mword eip = r->REG(ip);
    if (r->user())
        check_memory(1252);
    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }

    Ec* ec = current;
    if (r->user()){
        if (ec->is_temporal_exc()) {
            ec->enable_step_debug(RDTSC);
            return true;
        } else if (ec->is_io_exc()) {
            ec->resolve_PIO_execption();
            return true;
        }
    }
    Console::print("GP Here: Ec: %s  Pd: %s  err: %08lx  addr: %08lx  eip: %08lx  val: %lx Lapic::counter %llx", 
            ec->get_name(), ec->getPd()->get_name(), r->err, r->cr2, eip, *(reinterpret_cast<mword *> (eip)), Lapic::read_instCounter());

    if(ec->utcb){
        Console::print("eip0: %lx  rcx0: %lx  r11_0: %lx  rdi_0: %lx", regs_0.REG(ip), regs_0.REG(cx), regs_0.r11, regs_0.REG(di));
        Console::print("eip1: %lx  rcx1: %lx  r11_1: %lx  rdi_1: %lx", regs_1.REG(ip), regs_1.REG(cx), regs_1.r11, regs_1.REG(di));
    }else{
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
                    case MMIO:
                    case PIO:
                    case RDTSC:
                        //                        Console::print("EXC_DB step_reason: %d", step_reason);
                        if (not_nul_cowlist && step_reason != PIO) {
                            Console::print("cow_list not null was noticed Pd: %s", current->getPd()->get_name());
                            not_nul_cowlist = false;
                        }
                        if (current->getPd()->cow_list) {
                            if (step_reason != PIO)
                                Console::print("cow_list not null, noticed! Pd: %s", current->getPd()->get_name());
                            else {
                                not_nul_cowlist = true;
                            }
                        }
                        current->disable_step_debug();
                        launch_state = Ec::UNLAUNCHED;
                        reset_all();
                        return;
                    case PMI:
                        if (prev_rip == current->regs.REG(ip)) {
                            // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                            // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                            // It may happen that this is the final instruction
                            if ((current->regs.REG(ip) == end_rip) && (current->regs.REG(cx) == end_rcx)) {
                                current->disable_step_debug();
                                check_memory(3001);
                                return;
                            }
                        } else {
                            if (nbInstr_to_execute > 0)
                                nbInstr_to_execute--;
                        }
                        prev_rip = current->regs.REG(ip);
                        if (nbInstr_to_execute > 0) {
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                            return;
                        }
                        if ((current->regs.REG(ip) == end_rip) && (current->regs.REG(cx) == end_rcx)) {
//                            Console::print("EIP %lx|%lx  RCX: %lx|%lx  MSR_PERF_FIXED_CTR0: %lld  IA32_PMC0: %lld",
//                                    end_rip, current->regs.REG(ip), end_rcx, current->regs.REG(cx),
//                                    Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), Msr::read<uint64>(Msr::IA32_PMC0));

                            current->disable_step_debug();
                            check_memory(3001);
                            return;
                        } else {
                            // if(current->regs.REG(ip) == end_rip)
                            //      Console::print("RIP matches but RCX not");
                            // if(current->regs.REG(cx) == end_rcx)
                            //      Console::print("RCX matches but RIP not");
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                            nbInstr_to_execute = 1;
                            return;
                        }
                        break;
                    case GP:
                        return;
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
            //            if (Msr::read<uint64>(Msr::IA32_PERF_GLOBAL_STATUS) & 1ull << 32) {
            //                check_memory(3002);
            return;
            //            }
            break;

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

        case Cpu::EXC_AC:
            Console::print("Alignement check exception");

        case Cpu::EXC_MC:
            Mca::vector();
            break;
    }

    if (r->user()) {
        if (!is_idle() || current->getPd()->cow_list)
            check_memory(1256);
        send_msg<ret_user_iret>();
    }

    die("EXC", r);
}

void Ec::check_memory(int pmi) {
    Ec *ec = current;
    Pd *pd = ec->getPd();
//    if (is_idle())
//        Console::print("TCHA HOHO Must not be idle here, sth wrong. pmi: %d cowlist: %p Pd: %s", pmi, current->getPd()->cow_list, current->getPd()->get_name());
    if (!pd->cow_list) {
        launch_state = UNLAUNCHED;
        reset_all();
        return;
    }

//        Console::print("EIP = check_memory utcb %p run %d pmi %d counter %llx exc %lld rcx %lx eip %lx", ec->utcb, run_number, pmi, Lapic::read_instCounter(), exc_counter, current->regs.REG(cx), current->regs.REG(ip));
    if (one_run_ok()) {
        if (pmi == 3001) {
            step_debug_time = rdtsc();
        } else {
            runtime2 = rdtsc();
        }
        if (pmi == 3002) {
            if (pmi != prev_reason){
                    //means that pmi was simultaneous to another exception, which has been prioritized. 
                    //And the PMI is now to be serviced; but it does not matter anymore. Just launch the 2nd run.
                    Console::print("pmi different from previous_pmi");
                    check_exit();
            }
            exc_counter2 = exc_counter;
            counter2 = Lapic::read_instCounter();
            if (static_cast<long> (step_nb) > static_cast<long> (counter2 - exc_counter2)) {
                nbInstr_to_execute = step_nb - counter2 + exc_counter2;
                prev_rip = current->regs.REG(ip);
                Console::print("PMI inf utcb %p counter1 %llu exc1 %llu counter2 %llu exc2 %llu endrip %lx endrcx %lx", ec->utcb, counter1, exc_counter1, counter2, exc_counter2, end_rip, end_rcx);
                ec->enable_step_debug(PMI);
                ret_user_iret();
            } else if (static_cast<long> (step_nb) < static_cast<long> (counter2 - exc_counter2)) {
                //                if (step_reason != PIO)
                Console::print("PMI sup counter1 %llu exc1 %llu counter2 %llu exc2 %llu", counter1, exc_counter1, counter2, exc_counter2);
                ec->rollback();
                ec->reset_all();
                check_exit();
            } else {
                Console::print("PMI equal counter1 %llu exc1 %llu counter2 %llu exc2 %llu", counter1, exc_counter1, counter2, exc_counter2);
            }
        }
        ec->tour++;
        static_tour++;
        int reason = ec->compare_regs(pmi);
        bool cc = false;
        if (reason) {
            Console::print("REGS does not match utcb %p pmi %d  reason: %d Pd %s Ec %s", ec->utcb, pmi, reason, ec->getPd()->get_name(), ec->get_name());
            cc = true;
        }
        cc |= pd->compare_and_commit();
        if (cc) {
            Console::print("Checking failed Ec: %p  PMI: %d Pd: %s tour: %lld  s_tour: %lld  launch_state: %d", ec, pmi, pd->get_name(), ec->tour, static_tour, launch_state);
            Console::print("eip0: %lx  rcx0: %lx  r11_0: %lx  rdi_0: %lx", regs_0.REG(ip), regs_0.REG(cx), regs_0.r11, regs_0.REG(di));
            Console::print("eip1: %lx  rcx1: %lx  r11_1: %lx  rdi_1: %lx", regs_1.REG(ip), regs_1.REG(cx), regs_1.r11, regs_1.REG(di));
            Console::print("eip: %lx  rcx: %lx  r11: %lx  rdi: %lx", ec->regs.REG(ip), ec->regs.REG(cx), ec->regs.r11, ec->regs.REG(di));
            ec->rollback();
            ec->reset_all();
            check_exit();
        } else {
            launch_state = Ec::UNLAUNCHED;
            total_runtime = rdtsc();
            reset_all();
            return;
        }
    } else {
        //if reason is sysenter, end_time is not calculated so we better use rdtsc()
        runtime1 = end_time ? end_time : rdtsc();
        ec->tour++;
        static_tour++;
        ec->restore_state();
        run_number++;
        if (pmi == 3002) {
            prev_reason = pmi;
            end_rip = last_rip;
            end_rcx = last_rcx;
            exc_counter1 = exc_counter;
            counter1 = Lapic::read_instCounter();
            Lapic::program_pmi(static_cast<int>(step_nb - counter1 + exc_counter1));
            if (static_cast<long> (step_nb) < static_cast<long> (counter1 - exc_counter1))
                Console::print("step_nb too small utcb %p counter1 %llu exc1 %llu diff %ld", ec->utcb, counter1, exc_counter1, static_cast<long> (counter1 - exc_counter1));
            exc_counter = 0;
        } else {
            Lapic::cancel_pmi();
        }
        exc_counter = 0;
        check_exit();
    }

    return;
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
            Console::print("Bad Run");
            die("Bad Run");
    }
}

void Ec::reset_counter() {
    exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = 0;
    gsi_counter1 = lvt_counter1 = msi_counter1 = ipi_counter1 =
            gsi_counter2 = lvt_counter2 = msi_counter2 = ipi_counter2 = 0;
    Lapic::program_pmi();
}

void Ec::print_stat(bool pmi) {
    if (pmi) {
        Console::print("Overhead  Ec: %p tour: %lld  Ot1: %lld  db: %lld  Ocheck2: %lld  TT: %lld",
                current, current->tour, 10000 * runtime1 / total_runtime,
                10000 * (step_debug_time - runtime2) / total_runtime,
                10000 * (total_runtime - runtime2) / total_runtime,
                1000 * total_runtime / Lapic::freq_tsc
                );
    } else
        Console::print("Overhead  Ec: %p tour: %lld  Ot1: %lld  Ocheck2: %lld  TT: %lld",
            current, current->tour, 10000 * runtime1 / total_runtime,
            10000 * (total_runtime - runtime2) / total_runtime,
            1000 * total_runtime / Lapic::freq_tsc
            );
}

void Ec::reset_all() {
    current->pd->cow_list = nullptr;
    run_number = 0;
    reset_counter();
    reset_time();
    prev_reason = 0;
    no_further_check = false;
    reinterpret_cast<Space_pio*>(Pd::current->subspace(Crd::PIO))->enable_pio(Pd::current->quota);              
}

void Ec::reset_time() {
    runtime1 = 0;
    runtime2 = 0;
    total_runtime = 0;
    begin_time = end_time = 0; //if reason is sysenter, end_time could not be update so we have to reset it to 0 after every use
}