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
#include "string.hpp"

class Fpu
{
    private:
        char data[512];

        static Slab_cache cache;
        
        ALWAYS_INLINE
        static inline bool is_enabled() { return !(get_cr0() & (Cpu::CR0_TS|Cpu::CR0_EM)); }


    public:
        static Fpu *fpu_0, *fpu_1, *fpu_2;
        ALWAYS_INLINE
        inline void save() { asm volatile ("fxsave %0" : "=m" (*data)); }

        ALWAYS_INLINE
        inline void load() { asm volatile ("fxrstor %0" : : "m" (*data)); }

        ALWAYS_INLINE
        static inline void init() { asm volatile ("fninit"); }

        ALWAYS_INLINE
        static inline void enable() { asm volatile ("clts"); Cpu::hazard |= HZD_FPU; }
        
        ALWAYS_INLINE
        static inline void disable() { set_cr0 (get_cr0() | Cpu::CR0_TS); Cpu::hazard &= ~HZD_FPU; }

        ALWAYS_INLINE
        static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

        ALWAYS_INLINE
        static inline void destroy(Fpu *obj, Quota &quota) { obj->~Fpu(); cache.free (obj, quota); }
        
        void dwc_save(){ 
            if(is_enabled())
                fpu_0->save();
        }
        
        void dwc_restore(){
            if(is_enabled()){
                fpu_1->save();
                fpu_0->load();
            }
        }
        
        int dwc_check(){
            if(is_enabled()){
                fpu_2->save();
                return memcmp(fpu_1->data, fpu_2->data, 512);
            }
            return 0;
        }
        
        void dwc_rollback(){
            if(is_enabled())
                fpu_0->load();
        }
};
