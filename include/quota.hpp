/*
 * Quota tracking of buddy allocator
 *
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

#pragma once

#include "lock_guard.hpp"
#include "util.hpp"

class Buddy;

class Quota
{
    friend class Buddy;

    private:
        Spinlock lock;

        mword used;
        mword over;

        mword upli;
        mword notr;

    public:

        static Quota init;

        Quota () : used(0), over(0), upli(0), notr(0) { }

        void alloc(mword p)
        {
            Lock_guard <Spinlock> guard (lock);
            used += p;
        }

        void free(mword p)
        {
            Lock_guard <Spinlock> guard (lock);

            if (p <= used) {
                used -= p;
                return;
            }

            over += p - used;
            upli += p - used;
            used = 0;
        }

        mword usage() { return used; }

        static void boot(Quota &kern, Quota &root)
        {
            kern.upli   = kern.used;
            root.upli  -= kern.used;
        }

        void dump(void *, bool = true);
};
