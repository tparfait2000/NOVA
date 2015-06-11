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

class Buddy;

class Quota
{
    friend class Buddy;

    private:

        Spinlock lock;

        mword amount;
        mword freed;

        mword upli;
        mword notr;

    public:

        static Quota init;

        Quota () : amount(0), freed(0), upli(0), notr(0) { }

        void alloc(mword p)
        {
            Lock_guard <Spinlock> guard (lock);
            amount += p;
        }

        void free(mword p)
        {
            Lock_guard <Spinlock> guard (lock);
            freed += p;
        }

        mword usage() { return amount < freed ? 0 : amount - freed; }

        static void boot(Quota &kern, Quota &root)
        {
            kern.upli   = kern.amount;
            root.upli  -= kern.amount;
        }

        void dump(void *, bool = true);
};
