/*
 * Virtual Machine Extensions (VMX)
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

#pragma once

#include "assert.h"

class Vmcs
{
    public:
        uint32  rev;
        uint32  abort;

        static Vmcs *current CPULOCAL_HOT;

        static unsigned vpid_ctr CPULOCAL;

        static union vmx_basic {
            uint64      val;
            struct {
                uint32  revision;
                uint32  size        : 13,
                                    :  3,
                        width       :  1,
                        dual        :  1,
                        type        :  4,
                        insouts     :  1,
                        ctrl        :  1;
            };
        } basic CPULOCAL;

        static union vmx_ept_vpid {
            uint64      val;
            struct {
                uint32              : 16,
                        super       :  2,
                                    :  2,
                        invept      :  1,
                                    : 11;
                uint32  invvpid     :  1;
            };
        } ept_vpid CPULOCAL;

        static union vmx_ctrl_pin {
            uint64      val;
            struct {
                uint32  set, clr;
            };
        } ctrl_pin CPULOCAL;

        static union vmx_ctrl_cpu {
            uint64      val;
            struct {
                uint32  set, clr;
            };
        } ctrl_cpu[2] CPULOCAL;

        static union vmx_ctrl_exi {
            uint64      val;
            struct {
                uint32  set, clr;
            };
        } ctrl_exi CPULOCAL;

        static union vmx_ctrl_ent {
            uint64      val;
            struct {
                uint32  set, clr;
            };
        } ctrl_ent CPULOCAL;

        static union vmx_ctrl_misc {
            uint64      val;
            struct {
                uint32  ptmr_bits   :  5;
            };
        } ctrl_misc CPULOCAL;

        static mword fix_cr0_set CPULOCAL;
        static mword fix_cr0_clr CPULOCAL;
        static mword fix_cr4_set CPULOCAL;
        static mword fix_cr4_clr CPULOCAL;

        enum Encoding
        {
            // 16-Bit Control Fields
            VPID                    = 0x0000,

            // 16-Bit Guest State Fields
            GUEST_SEL_ES            = 0x0800,
            GUEST_SEL_CS            = 0x0802,
            GUEST_SEL_SS            = 0x0804,
            GUEST_SEL_DS            = 0x0806,
            GUEST_SEL_FS            = 0x0808,
            GUEST_SEL_GS            = 0x080a,
            GUEST_SEL_LDTR          = 0x080c,
            GUEST_SEL_TR            = 0x080e,

            // 16-Bit Host State Fields
            HOST_SEL_ES             = 0x0c00,
            HOST_SEL_CS             = 0x0c02,
            HOST_SEL_SS             = 0x0c04,
            HOST_SEL_DS             = 0x0c06,
            HOST_SEL_FS             = 0x0c08,
            HOST_SEL_GS             = 0x0c0a,
            HOST_SEL_TR             = 0x0c0c,

            // 64-Bit Control Fields
            IO_BITMAP_A             = 0x2000,
            IO_BITMAP_B             = 0x2002,
            MSR_BITMAP              = 0x2004,
            EXI_MSR_ST_ADDR         = 0x2006,
            EXI_MSR_LD_ADDR         = 0x2008,
            ENT_MSR_LD_ADDR         = 0x200a,
            VMCS_EXEC_PTR           = 0x200c,
            TSC_OFFSET              = 0x2010,
            TSC_OFFSET_HI           = 0x2011,
            APIC_VIRT_ADDR          = 0x2012,
            APIC_ACCS_ADDR          = 0x2014,
            EPTP                    = 0x201a,
            EPTP_HI                 = 0x201b,

            INFO_PHYS_ADDR          = 0x2400,

            // 64-Bit Guest State
            VMCS_LINK_PTR           = 0x2800,
            VMCS_LINK_PTR_HI        = 0x2801,
            GUEST_DEBUGCTL          = 0x2802,
            GUEST_DEBUGCTL_HI       = 0x2803,
            GUEST_EFER              = 0x2806,
            GUEST_PERF_GLOBAL_CTRL  = 0x2808,
            GUEST_PDPTE             = 0x280a,

            // 64-Bit Host State
            HOST_EFER               = 0x2c02,
            HOST_PERF_GLOBAL_CTRL   = 0x2c04,

            // 32-Bit Control Fields
            PIN_CONTROLS            = 0x4000,
            CPU_EXEC_CTRL0          = 0x4002,
            EXC_BITMAP              = 0x4004,
            PF_ERROR_MASK           = 0x4006,
            PF_ERROR_MATCH          = 0x4008,
            CR3_TARGET_COUNT        = 0x400a,
            EXI_CONTROLS            = 0x400c,
            EXI_MSR_ST_CNT          = 0x400e,
            EXI_MSR_LD_CNT          = 0x4010,
            ENT_CONTROLS            = 0x4012,
            ENT_MSR_LD_CNT          = 0x4014,
            ENT_INTR_INFO           = 0x4016,
            ENT_INTR_ERROR          = 0x4018,
            ENT_INST_LEN            = 0x401a,
            TPR_THRESHOLD           = 0x401c,
            CPU_EXEC_CTRL1          = 0x401e,

            // 32-Bit R/O Data Fields
            VMX_INST_ERROR          = 0x4400,
            EXI_REASON              = 0x4402,
            EXI_INTR_INFO           = 0x4404,
            EXI_INTR_ERROR          = 0x4406,
            IDT_VECT_INFO           = 0x4408,
            IDT_VECT_ERROR          = 0x440a,
            EXI_INST_LEN            = 0x440c,
            EXI_INST_INFO           = 0x440e,

            // 32-Bit Guest State Fields
            GUEST_LIMIT_ES          = 0x4800,
            GUEST_LIMIT_CS          = 0x4802,
            GUEST_LIMIT_SS          = 0x4804,
            GUEST_LIMIT_DS          = 0x4806,
            GUEST_LIMIT_FS          = 0x4808,
            GUEST_LIMIT_GS          = 0x480a,
            GUEST_LIMIT_LDTR        = 0x480c,
            GUEST_LIMIT_TR          = 0x480e,
            GUEST_LIMIT_GDTR        = 0x4810,
            GUEST_LIMIT_IDTR        = 0x4812,
            GUEST_AR_ES             = 0x4814,
            GUEST_AR_CS             = 0x4816,
            GUEST_AR_SS             = 0x4818,
            GUEST_AR_DS             = 0x481a,
            GUEST_AR_FS             = 0x481c,
            GUEST_AR_GS             = 0x481e,
            GUEST_AR_LDTR           = 0x4820,
            GUEST_AR_TR             = 0x4822,
            GUEST_INTR_STATE        = 0x4824,
            GUEST_ACTV_STATE        = 0x4826,
            GUEST_SMBASE            = 0x4828,
            GUEST_SYSENTER_CS       = 0x482a,
            PREEMPTION_TIMER        = 0x482e,

            // 32-Bit Host State Fields
            HOST_SYSENTER_CS        = 0x4c00,

            // Natural-Width Control Fields
            CR0_MASK                = 0x6000,
            CR4_MASK                = 0x6002,
            CR0_READ_SHADOW         = 0x6004,
            CR4_READ_SHADOW         = 0x6006,
            CR3_TARGET_0            = 0x6008,
            CR3_TARGET_1            = 0x600a,
            CR3_TARGET_2            = 0x600c,
            CR3_TARGET_3            = 0x600e,

            // Natural-Width R/O Data Fields
            EXI_QUALIFICATION       = 0x6400,
            IO_RCX                  = 0x6402,
            IO_RSI                  = 0x6404,
            IO_RDI                  = 0x6406,
            IO_RIP                  = 0x6408,
            GUEST_LINEAR_ADDRESS    = 0x640a,

            // Natural-Width Guest State Fields
            GUEST_CR0               = 0x6800,
            GUEST_CR3               = 0x6802,
            GUEST_CR4               = 0x6804,
            GUEST_BASE_ES           = 0x6806,
            GUEST_BASE_CS           = 0x6808,
            GUEST_BASE_SS           = 0x680a,
            GUEST_BASE_DS           = 0x680c,
            GUEST_BASE_FS           = 0x680e,
            GUEST_BASE_GS           = 0x6810,
            GUEST_BASE_LDTR         = 0x6812,
            GUEST_BASE_TR           = 0x6814,
            GUEST_BASE_GDTR         = 0x6816,
            GUEST_BASE_IDTR         = 0x6818,
            GUEST_DR7               = 0x681a,
            GUEST_RSP               = 0x681c,
            GUEST_RIP               = 0x681e,
            GUEST_RFLAGS            = 0x6820,
            GUEST_PENDING_DEBUG     = 0x6822,
            GUEST_SYSENTER_ESP      = 0x6824,
            GUEST_SYSENTER_EIP      = 0x6826,

            // Natural-Width Host State Fields
            HOST_CR0                = 0x6c00,
            HOST_CR3                = 0x6c02,
            HOST_CR4                = 0x6c04,
            HOST_BASE_FS            = 0x6c06,
            HOST_BASE_GS            = 0x6c08,
            HOST_BASE_TR            = 0x6c0a,
            HOST_BASE_GDTR          = 0x6c0c,
            HOST_BASE_IDTR          = 0x6c0e,
            HOST_SYSENTER_ESP       = 0x6c10,
            HOST_SYSENTER_EIP       = 0x6c12,
            HOST_RSP                = 0x6c14,
            HOST_RIP                = 0x6c16,
        };

        enum Ctrl_exi
        {
            EXI_HOST_64             = 1UL << 9,
            EXI_INTA                = 1UL << 15,
            EXI_LOAD_EFER           = 1UL << 21,
            EXI_SAVE_PTMR           = 1UL << 22,
        };

        enum Ctrl_ent
        {
            ENT_GUEST_64            = 1UL << 9,
            ENT_LOAD_EFER           = 1UL << 15,
        };

        enum Ctrl_pin
        {
            PIN_EXTINT              = 1UL << 0,
            PIN_NMI                 = 1UL << 3,
            PIN_VIRT_NMI            = 1UL << 5,
            PIN_PTMR                = 1UL << 6,
        };

        enum Ctrl0
        {
            CPU_INTR_WINDOW         = 1UL << 2,
            CPU_HLT                 = 1UL << 7,
            CPU_INVLPG              = 1UL << 9,
            CPU_CR3_LOAD            = 1UL << 15,
            CPU_CR3_STORE           = 1UL << 16,
            CPU_NMI_WINDOW          = 1UL << 22,
            CPU_IO                  = 1UL << 24,
            CPU_IO_BITMAP           = 1UL << 25,
            CPU_SECONDARY           = 1UL << 31,
        };

        enum Ctrl1
        {
            CPU_EPT                 = 1UL << 1,
            CPU_VPID                = 1UL << 5,
            CPU_URG                 = 1UL << 7,
        };

        enum Reason
        {
            VMX_EXC_NMI             = 0,
            VMX_EXTINT              = 1,
            VMX_TRIPLE_FAULT        = 2,
            VMX_INIT                = 3,
            VMX_SIPI                = 4,
            VMX_SMI_IO              = 5,
            VMX_SMI_OTHER           = 6,
            VMX_INTR_WINDOW         = 7,
            VMX_NMI_WINDOW          = 8,
            VMX_TASK_SWITCH         = 9,
            VMX_CPUID               = 10,
            VMX_GETSEC              = 11,
            VMX_HLT                 = 12,
            VMX_INVD                = 13,
            VMX_INVLPG              = 14,
            VMX_RDPMC               = 15,
            VMX_RDTSC               = 16,
            VMX_RSM                 = 17,
            VMX_VMCALL              = 18,
            VMX_VMCLEAR             = 19,
            VMX_VMLAUNCH            = 20,
            VMX_VMPTRLD             = 21,
            VMX_VMPTRST             = 22,
            VMX_VMREAD              = 23,
            VMX_VMRESUME            = 24,
            VMX_VMWRITE             = 25,
            VMX_VMXOFF              = 26,
            VMX_VMXON               = 27,
            VMX_CR                  = 28,
            VMX_DR                  = 29,
            VMX_IO                  = 30,
            VMX_RDMSR               = 31,
            VMX_WRMSR               = 32,
            VMX_FAIL_STATE          = 33,
            VMX_FAIL_MSR            = 34,
            VMX_MWAIT               = 36,
            VMX_MTF                 = 37,
            VMX_MONITOR             = 39,
            VMX_PAUSE               = 40,
            VMX_FAIL_MCHECK         = 41,
            VMX_TPR_THRESHOLD       = 43,
            VMX_APIC_ACCESS         = 44,
            VMX_GDTR_IDTR           = 46,
            VMX_LDTR_TR             = 47,
            VMX_EPT_VIOLATION       = 48,
            VMX_EPT_MISCONFIG       = 49,
            VMX_INVEPT              = 50,
            VMX_PREEMPT             = 52,
            VMX_INVVPID             = 53,
            VMX_WBINVD              = 54,
            VMX_XSETBV              = 55
        };

        ALWAYS_INLINE
        static inline void *operator new (size_t)
        {
            return Buddy::allocator.alloc (0, Buddy::NOFILL);
        }

        Vmcs (mword, mword, mword, uint64);

        ALWAYS_INLINE
        inline Vmcs() : rev (basic.revision)
        {
            uint64 phys = Buddy::ptr_to_phys (this);

            bool ret;
            asm volatile ("vmxon %1; seta %0" : "=q" (ret) : "m" (phys) : "cc");
            assert (ret);
        }

        ALWAYS_INLINE
        inline void clear()
        {
            uint64 phys = Buddy::ptr_to_phys (this);

            bool ret;
            asm volatile ("vmclear %1; seta %0" : "=q" (ret) : "m" (phys) : "cc");
            assert (ret);
        }

        ALWAYS_INLINE
        inline void make_current()
        {
            if (EXPECT_TRUE (current == this))
                return;

            uint64 phys = Buddy::ptr_to_phys (current = this);

            bool ret;
            asm volatile ("vmptrld %1; seta %0" : "=q" (ret) : "m" (phys) : "cc");
            assert (ret);
        }

        ALWAYS_INLINE
        static inline mword read (Encoding enc)
        {
            mword val;
            asm volatile ("vmread %1, %0" : "=rm" (val) : "r" (static_cast<mword>(enc)) : "cc");
            return val;
        }

        ALWAYS_INLINE
        static inline void write (Encoding enc, mword val)
        {
            asm volatile ("vmwrite %0, %1" : : "rm" (val), "r" (static_cast<mword>(enc)) : "cc");
        }

        ALWAYS_INLINE
        static inline void adjust_rip()
        {
            write (GUEST_RIP, read (GUEST_RIP) + read (EXI_INST_LEN));

            uint32 intr = static_cast<uint32>(read (GUEST_INTR_STATE));
            if (EXPECT_FALSE (intr & 3))
                write (GUEST_INTR_STATE, intr & ~3);
        }

        ALWAYS_INLINE
        static inline unsigned long vpid()
        {
            return has_vpid() ? read (VPID) : 0;
        }

        static bool has_secondary() { return ctrl_cpu[0].clr & CPU_SECONDARY; }
        static bool has_ept()       { return ctrl_cpu[1].clr & CPU_EPT; }
        static bool has_vpid()      { return ctrl_cpu[1].clr & CPU_VPID; }
        static bool has_urg()       { return ctrl_cpu[1].clr & CPU_URG; }
        static bool has_vnmi()      { return ctrl_pin.clr & PIN_VIRT_NMI; }

        static void init();
};
