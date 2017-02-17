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

    if ((r->err & Hpt::ERR_U) && Pd::current->Space_mem::loc[Cpu::id].is_cow_fault(Pd::current->quota, addr, r->err)) {
        current->cow_faulted = true;
        return true;
    }
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
                current->runtime2 = rdtsc() - begin_time;
                current->in_step_mode = true;
                current->regs.REG(fl) |= Cpu::EFL_TF;
                uint64 instr_count = Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0);
                if(instr_count > step_nb){
                    Console::print("OVERFLOW OF EXECUTION, increase step_nb");
                    die("OVERFLOW OF EXECUTION, increase step_nb");
                }
                compteur = step_nb - instr_count + 1;
                prev_rip = current->regs.REG(ip);
                instr_count0 = instr_count;
                //                Console::print("PERF INTERRUPT OVERFLOW MSR_PERF_FIXED_CTR0 %lld  compteur %u", instr_count, compteur);
                return;
            }
            break;
        case Cpu::EXC_DB:
            if (current->in_step_mode) {
                if (prev_rip == current->regs.REG(ip)) {
                    //                    Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                    //                        current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                    //It may happen that this is the final instruction
                    if ((current->regs.REG(ip) == end_rip) && (current->regs.REG(cx) == end_rcx)) {
                        compteur = 0;
                        current->regs.REG(fl) &= ~Cpu::EFL_TF;
                        current->in_step_mode = false;
                        check_memory(3001);
                        return;
                    }
                } else {
                    compteur--;
                }
                prev_rip = current->regs.REG(ip);
                //                if(Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0) - instr_count0 != 2){
                //                    Console::print("EIP: %lx  MSR_PERF_FIXED_CTR0: %lld instr_count0: %u instr: %lx", 
                //                        current->regs.REG(ip), Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), instr_count0, *reinterpret_cast<mword *>(current->regs.REG(ip)));
                //                }
                //                instr_count0 = Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0);
                if (compteur > 0) {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    return;
                }
                //                Console::print("EIP %lx|%lx  RCX: %lx|%lx  MSR_PERF_FIXED_CTR0: %lld  IA32_PMC0: %lld", 
                //                        end_rip, current->regs.REG(ip), end_rcx, current->regs.REG(cx),
                //                        Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), Msr::read<uint64>(Msr::IA32_PMC0));
                if ((current->regs.REG(ip) == end_rip) && (current->regs.REG(cx) == end_rcx)) {
                    compteur = 0;
                    current->regs.REG(fl) &= ~Cpu::EFL_TF;
                    current->in_step_mode = false;
                    check_memory(3001);
                    return;
                } else {
                    //                    if(current->regs.REG(ip) == end_rip)
                    //                        Console::print("RIP matches but RCX not");
                    //                    if(current->regs.REG(cx) == end_rcx)
                    //                        Console::print("RCX matches but RIP not");
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    compteur = 1;
                    return;
                }
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
        ec->reset_counter();
        return;
    }

    //    if (!current->user_utcb) {
    //        Console::print(".....  Checking memory from %d ", pmi);
    //        //        current->ec_debug= true;
    //    }
    if (ec->one_run_ok()) {
        if (pmi == 1251) {
            //            Console::print("PMI = 1251 en 2nd run");
            return;
        }
        if(pmi == 3001){
            ec->step_debug_time = rdtsc() - begin_time;
        }else{
            ec->runtime2 = rdtsc() - begin_time; 
        }
        ec->exc_counter2 = Ec::exc_counter;
        ec->counter2 = readReset_instCounter();
        ec->tour++;
        static_tour++;
        //        if (ec_debug) {
        //            Console::print("PMI: %d  counters: %lld | %lld  exc: %d | %d Run = 2  PMC0: %lld  EIP: %lx  RCX: %lx", 
        //                    pmi, ec->counter1, ec->counter2, ec->exc_counter1, ec->exc_counter2,
        //                    Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip), ec->regs.REG(cx));
        //        }
        //        if (pmi == 3001) {
        //            Console::print("PMI: %d  counter2: %lld  exc: %d Run = 2  PMC0: %lld  EIP: %lx tour: %lld  s_tour: %lld",
        //                    pmi, ec->counter2, ec->exc_counter2, Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip), ec->tour, static_tour);
        //        }
        ec->reset_counter();
        int reason = ec->compare_ok(pmi);
        if (reason)
            Console::print("REGS does not match %d  reason: %d  tour: %lld  s_tour: %lld", pmi, reason, ec->tour, static_tour);
        if (pd->compare_and_commit()) {
            pd->cow_list = nullptr;
            ec->run_number = 0;
            ec->launch_state = Ec::UNLAUNCHED;
            ec->total_runtime = rdtsc() - begin_time;
//            if (ec_debug) {
//                ec->print_stat_reset(true);
//                ec_debug = false;
//            } else if (ec->tour % ec->affich_mod == 0) {
//                ec->affich_num++;
//                ec->affich_mod += 1000 * (ec->affich_num / 10);
//                ec->print_stat_reset(false);
//            }
            return;
        } else {
            Console::print("Checking failed Ec: %p  PMI: %d tour: %lld  s_tour: %lld", ec, pmi, ec->tour, static_tour);
            ec->rollback();
            ec->run_number = 0;
            pd->cow_list = nullptr;
            check_exit(ec);
        }
    } else {
        ec->exc_counter1 = exc_counter;
        ec->counter1 = readReset_instCounter();
        uint64 instruction_num = ec->counter1 - exc_counter1;
        if (pmi == 1251 && instruction_num <= 0) {
            //            Console::print("instruction_num: %lld", instruction_num);
            return;
        }
        //if reason is sysenter, end_time is not calculated so we better use rdtsc() - begin_time
        ec->runtime1 = end_time ? end_time : rdtsc() - begin_time;
        ec->tour++;
        static_tour++;
        //        Console::print("PMI: %d  counter1: %lld  exc: %u Run = 1  PMC0: %lld  EIP: %lx  RCX: %lx tour: %lld  s_tour: %lld",
        //            pmi, ec->counter1, ec->exc_counter1, Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip), ec->regs.REG(cx), ec->tour, static_tour);
        ec->restore_state();
        ec->run_number++;
        if (pmi == 1251) {
//            Console::print("PMI: %d  counter1: %lld  exc: %u Run = 1  PMC0: %lld  EIP: %lx  RCX: %lx tour: %lld  s_tour: %lld",
//                    pmi, ec->counter1, ec->exc_counter1, Msr::read<uint64>(Msr::IA32_PMC0), ec->regs.REG(ip), ec->regs.REG(cx), ec->tour, static_tour);
            ec->activate_timer();
            ec_debug = true;
        }
        Msr::write(Msr::IA32_PERFEVTSEL0, 0x000100c5);
        Msr::write(Msr::IA32_PMC0, 0x0);
        Msr::write(Msr::IA32_PERFEVTSEL0, 0x004100c5);
        check_exit(ec);
    }

    return;
}

void Ec::check_exit(Ec *ec) {
    t_check1 = rdtsc() - begin_time;
//    wbinvd();
    t_cache = rdtsc() - begin_time;
    set_ti = true;
    switch (ec->launch_state) {
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

bool Ec::activate_timer() {
    uint64 instruction_num = counter1 - exc_counter1;
    if (instruction_num > step_nb) {
        Lapic::set_pmi(instruction_num - step_nb);
    } else {
        if (instruction_num > 0) {
            current->runtime2 = rdtsc() - begin_time;
            in_step_mode = true;
            regs.REG(fl) |= Cpu::EFL_TF;
            nbInstr_to_execute = instruction_num;
            compteur = instruction_num;
            if (launch_state == SYSEXIT) {
                compteur++;
            }
        } else {
            return false;
        }
    }
    return true;
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

void Ec::print_stat_reset(bool pmi) {
    if(pmi){
        Console::print("Overhead  Ec: %p tour: %lld  Ot1: %lld  Ocheck1: %lld  Ocache: %lld  Oexit: %lld  Ot2: %lld  db: %lld  Ocheck2: %lld O: %lld  TT: %lld",
            this, tour, 10000 * runtime1 / total_runtime,
            10000 * (t_check1 - runtime1) / total_runtime,
            10000 * (t_cache - t_check1) / total_runtime,
            10000 * (t_intermediary - t_cache) / total_runtime,
            10000 * (runtime2 - t_intermediary) / total_runtime,
            10000 * (step_debug_time - runtime2) / total_runtime,
            10000 * (total_runtime - runtime2) / total_runtime,
            10000 * total_runtime / (runtime2 - t_intermediary),
            1000 * total_runtime / Lapic::freq_tsc
            );
    }else
        Console::print("Overhead  Ec: %p tour: %lld  Ot1: %lld  Ocheck1: %lld  Ocache: %lld  Oexit: %lld  Ot2: %lld  Ocheck2: %lld O: %lld  TT: %lld",
            this, tour, 10000 * runtime1 / total_runtime,
            10000 * (t_check1 - runtime1) / total_runtime,
            10000 * (t_cache - t_check1) / total_runtime,
            10000 * (t_intermediary - t_cache) / total_runtime,
            10000 * (runtime2 - t_intermediary) / total_runtime,
            10000 * (total_runtime - runtime2) / total_runtime,
            10000 * total_runtime / (runtime2 - t_intermediary),
            1000 * total_runtime / Lapic::freq_tsc
            );
    runtime1 = 0;
    runtime2 = 0;
    total_runtime = 0;
    end_time = 0; //if reason is sysenter, end_time could not be update so we have to reset it to 0 after every use
}