/*
 * Floating Point Unit (FPU)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#include "fpu.hpp"
#include "pd.hpp"

INIT_PRIORITY (PRIO_SLAB)
Slab_cache Fpu::cache (sizeof (Fpu), 16);
Fpu *Fpu::fpu_0 = new(Pd::kern.quota) Fpu, *Fpu::fpu_1 = new(Pd::kern.quota) Fpu, *Fpu::fpu_2 = new(Pd::kern.quota) Fpu;

