/*
 * Floating Point Unit (FPU)
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

#include "cpu.hpp"
#include "hazards.hpp"
#include "slab.hpp"
#include "x86.hpp"
#include "pd.hpp"

class Fpu
{
    private:
        union {
            char data[512];
            struct {
                uint16 fcw;
                uint16 fsw;
                uint8  ftw;
                uint8  res;
                uint16 fop;
                uint64 fip;
                uint64 fdp;
                uint32 mxcsr;
                uint32 mxcsr_mask;
            };
        };

    public:
        ALWAYS_INLINE
        inline void save() { asm volatile ("fxsave %0" : "=m" (*data)); }

        ALWAYS_INLINE
        inline void load() { asm volatile ("fxrstor %0" : : "m" (*data)); }

        static void init();

        ALWAYS_INLINE
        static inline void enable() { asm volatile ("clts"); Cpu::hazard |= HZD_FPU; }

        ALWAYS_INLINE
        static inline void disable() { set_cr0 (get_cr0() | Cpu::CR0_TS); Cpu::hazard &= ~HZD_FPU; }

        ALWAYS_INLINE
        static inline void *operator new (size_t, Pd &pd) { return pd.fpu_cache.alloc(pd.quota); }

        ALWAYS_INLINE
        static inline void destroy(Fpu *obj, Pd &pd) { obj->~Fpu(); pd.fpu_cache.free (obj, pd.quota); }

        Fpu()
        {
            // Mask exceptions by default according to SysV ABI spec.
            fcw = 0x37f;
            mxcsr = 0x1f80;
        }
};
