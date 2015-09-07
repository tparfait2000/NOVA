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

        void free_up(Quota &to)
        {
            mword l, a, f;
            {
                Lock_guard <Spinlock> guard (lock);
                l = upli;
                a = amount;
                f = freed;
                upli = amount = freed = 0;
            }

            Lock_guard <Spinlock> guard (to.lock);
            to.upli += l;
            to.amount += a;
            to.freed += f;
        }

        bool hit_limit(mword free_space = 0)
        {
             if (free_space > upli)
                 return true;

             return usage() > upli - free_space;
        }

        bool transfer_to(Quota &to, mword transfer, bool check_notr = true)
        {
             {
                 Lock_guard <Spinlock> guard (lock);

                 if (hit_limit()) return false;

                 mword not_for_transfer = check_notr ? notr : 0;

                 if (usage() + transfer > upli - not_for_transfer) return false;

                 upli -= transfer;
             }

             Lock_guard <Spinlock> guard (to.lock);
             to.upli += transfer;
             return true;
        }

        bool set_limit(mword l, mword h, Quota &from)
        {
            if (!from.transfer_to(*this, h))
                return false;

            notr = l;
            return true;
        }

        mword limit() { return upli; }

        void dump(void *, bool = true);
};

class Quota_guard
{
    private:

        Quota q;
        Quota &r;

    public:

        Quota_guard(Quota &ref) : q(), r(ref) { }

        bool check(mword req)
        {
            if (!q.hit_limit(req))
                return true;

            if (q.limit() <= q.usage())
                req += q.usage() - q.limit();
            else
                req = q.limit() - q.usage();

            return r.transfer_to(q, req, false);
        }

        operator Quota&() { return q; }

        ~Quota_guard() { q.free_up(r); }
};
