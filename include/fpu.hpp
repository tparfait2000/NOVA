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
        static unsigned const data_size = 512, state_size = 108;
        char data[data_size];
        static char statedata[state_size], statedata_0[state_size], statedata_1[state_size], statedata_2[state_size], data_0[data_size], data_1[data_size] ;
        static Slab_cache cache;
        
        ALWAYS_INLINE
        static inline bool is_enabled() { return !(get_cr0() & (Cpu::CR0_TS|Cpu::CR0_EM)); }

        ALWAYS_INLINE
        inline void save_state(char* to) { asm volatile ("fsave %0" : "=m" (*to)); }

        ALWAYS_INLINE
        inline void load_state(char *from) { asm volatile ("frstor %0" : : "m" (*from)); }

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
//            if(is_enabled()){
                fpu_0->save();
                memcpy(data_0, data, data_size);
                save_state(Fpu::statedata_0);
                load_state(Fpu::statedata_0);
//            }
        }
        
        void dwc_restore(){
//            if(is_enabled()){
                fpu_1->save();
                memcpy(data_1, data, data_size);
                save_state(Fpu::statedata_1);
                fpu_0->load();
                memcpy(data, data_0, data_size);
                load_state(statedata_0);
//            }
        }
        
        int dwc_check(){
//            if(is_enabled()){
                fpu_2->save();
                save_state(Fpu::statedata_2);
                return memcmp(fpu_1->data, fpu_2->data, data_size)+memcmp(statedata_1, statedata_2, state_size);
//            }
            return 0;
        }
        
        void dwc_rollback(){
//            if(is_enabled()){
                fpu_0->load();
                memcpy(data, data_0, data_size);
                load_state(statedata_0);
//            }
        }
};
