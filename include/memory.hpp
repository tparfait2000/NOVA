/*
 * Virtual-Memory Layout
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

#define PAGE_BITS       12
#define PAGE_SIZE       (1 << PAGE_BITS)
#define PAGE_MASK       (PAGE_SIZE - 1)

#define AP_BOOT_PADDR   0x1000
#define LOAD_ADDR       0x200000

#if     defined(__i386__)
#define USER_ADDR       0xc0000000
#define LINK_ADDR       0xc0000000
#define CPU_LOCAL       0xcfc00000
#define SPC_LOCAL       0xd0000000
#elif   defined(__x86_64__)
#define USER_ADDR       0x00007fffc0000000
#define LINK_ADDR       0xffffffff81000000
#define CPU_LOCAL       0xffffffffbfe00000
#define SPC_LOCAL       0xffffffffc0000000
#endif

#define HV_GLOBAL_CPUS  (CPU_LOCAL - 0x1000000)
#define HV_GLOBAL_LBUF  (CPU_LOCAL - PAGE_SIZE * 1)
#define HV_GLOBAL_FBUF  (CPU_LOCAL - PAGE_SIZE * 2)
/* (CPU_LOCAL - PAGE_SIZE * 3) used by ioapic/dmar/pci !!! hwdev_addr (hwdev_addr = HV_GLOBAL_FBUF) - PAGE_SIZE !!! */

#define CPU_LOCAL_STCK  (SPC_LOCAL - PAGE_SIZE * 6)
#define CPU_LOCAL_APIC  (SPC_LOCAL - PAGE_SIZE * 4)
#define CPU_LOCAL_DATA  (SPC_LOCAL - PAGE_SIZE * 2)

#define SPC_LOCAL_IOP   (SPC_LOCAL)                     //0xd0000000    0xFFFFFFFFC0000000
#define SPC_LOCAL_IOP_E (SPC_LOCAL_IOP + PAGE_SIZE * 2) //0xd0002000    0xFFFFFFFFC0002000    
#define SPC_LOCAL_REMAP (SPC_LOCAL_OBJ - 0x1000000)     //0xdf000000    0xFFFFFFFFDF000000
#define SPC_LOCAL_OBJ   (END_SPACE_LIM - 0x20000000)    //0xe0000000    0xFFFFFFFFE0000000

#define COW_ADDR        (LINK_ADDR - 0x40000000)   //0xde000000    0xFFFFFFFF80000000
#define LOCAL_IOP_REMAP (COW_ADDR - 0x1000000)          //0xdd000000    0xFFFFFFFF7F000000
#define NB_COW_FRAME_ORDER    12  // means 2¹⁴ = 16 * 1024 frames
#define NB_COW_FRAME    (0x26UL << NB_COW_FRAME_ORDER)  // (384-32)*1024/4 car une page = 4Ko
#define NB_COW_ELT      (NB_COW_FRAME)
#define NB_TS_ELT       10000
#define NB_BLOCK_ELT    20
#define END_SPACE_LIM   (~0UL + 1)
