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

Pt::Pt (Pd *own, mword sel, Ec *e, Mtd m, mword addr) : Kobject (PT, static_cast<Space_obj *>(own), sel, PERM_CTRL | PERM_CALL | PERM_XCPU, free), ec (e), mtd (m), ip (addr), id(0)
{
    trace (TRACE_SYSCALL, "PT:%p created (EC:%p IP:%#lx)", this, e, ip);
}

void * Pt::operator new (size_t, Pd &pd)
{
     return pd.pt_cache.alloc(pd.quota);
}

void Pt::destroy(Pt *obj)
{
    Pd &pd = *obj->ec->pd;
    obj->~Pt(); pd.pt_cache.free (obj, pd.quota);
}

void Pt::free (Rcu_elem * p)
{
    Pt *pt = static_cast<Pt *>(p);

    if (!pt->del_ref())
        return;

    Pt::destroy(pt);
}
