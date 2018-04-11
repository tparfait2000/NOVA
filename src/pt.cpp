/*
 * Portal
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2015 Alexander Boettcher, Genode Labs GmbH
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
#include "pt.hpp"
#include "stdio.hpp"

INIT_PRIORITY (PRIO_SLAB)
Slab_cache Pt::cache (sizeof (Pt), 32);

Pt::Pt (Pd *own, mword sel, Ec *e, Mtd m, mword addr) : Kobject (PT, static_cast<Space_obj *>(own), sel, 0x3, free), ec (e), mtd (m), ip (addr), id(0)
{
    trace (TRACE_SYSCALL, "PT:%p created (EC:%p IP:%#lx)", this, e, ip);
}

void Pt::free (Rcu_elem * p)
{
    Pt *pt = static_cast<Pt *>(p);

    if (!pt->del_ref())
        return;

    Pd *pd = static_cast<Pd *>(static_cast<Space_obj *>(pt->space));
    destroy(pt, pd->quota);
}
