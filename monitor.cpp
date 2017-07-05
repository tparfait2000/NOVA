/*
 * QEMU monitor
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "x86.hpp"
#include "cpu.hpp"
#include "hpt.hpp"
#include "types.hpp"

/**
 * PTLayout describes the layout of an x86 page table in enough detail
 * to fully decode up to a 4-level 64-bit page table tree.
 */
typedef struct PTLayout {
    int levels, entsize;
    int entries[4];             /* Entries in each table level */
    int shift[4];               /* VA bit shift each each level */
    bool pse[4];                /* Whether PSE bit is valid */
    const char *names[4];
    int vaw, paw;               /* VA and PA width in characters */
} PTLayout;

/**
 * PTIter provides a generic way to traverse and decode an x86 page
 * table tree.
 */
typedef struct PTIter {
    const PTLayout *layout;
    bool pse;                   /* PSE enabled */
    int level;                  /* Current level */
    int i[4];                   /* Index at each level */
    uint64 base[4];             /* Physical base pointer */

    uint64 ent;               /* Current entry */
    bool present, leaf;
    mword va;
    uint64 pa;
    mword  size;
} PTIter;

static bool ptiter_succ(PTIter *it);

/**
 * Initialize a PTIter to point to the first entry of the page table's
 * top level.  On failure, prints a message to mon and returns false.
 */
static bool ptiter_init(mword cr3, PTIter *it)
{
    static const PTLayout l32 = {
        2, 4, {1024, 1024}, {22, 12}, {1, 0}, {"PDE", "PTE"}, 8, 8
    };
    static const PTLayout lpae = {
        3, 8, {4, 512, 512}, {30, 21, 12}, {0, 1, 0},
        {"PDP", "PDE", "PTE"}, 8, 13
    };
#ifdef  __x86_64__
    static const PTLayout l64 = {
        4, 8, {512, 512, 512, 512}, {39, 30, 21, 12}, {0, 1, 1, 0},
        {"PML4", "PDP", "PDE", "PTE"}, 12, 13
    };
#endif

    if (!(get_cr0() & Cpu::CR0_PG)) {
        Console::print("PG disabled\n");
        return false;
    }

    memset(it, 0, sizeof(*it));
    if (get_cr4() & Cpu::CR4_PAE) {
//#ifdef  __x86_64__
//        if (env->hflags & HF_LMA_MASK) {
//            it->layout = &l64;
//            it->base[0] = env->cr[3] & 0x3fffffffff000ULL;
//        } else
//#endif
        {
            it->layout = &lpae;
            it->base[0] = cr3 & ~0x1f;
        }
        it->pse = true;
    } else {
        it->layout = &l32;
        it->base[0] = cr3 & ~0xfff;
        it->pse = (get_cr4() & Cpu::CR4_PSE);
    }

    /* Trick ptiter_succ into doing the hard initialization. */
    it->i[0] = -1;
    it->leaf = true;
    ptiter_succ(it);
    return true;
}

/**
 * Move a PTIter to the successor of the current entry.  Specifically:
 * if the iterator points to a leaf, move to its next sibling, or to
 * the next sibling of a parent if it has no more siblings.  If the
 * iterator points to a non-leaf, move to its first child.  If there
 * is no successor, return false.
 *
 * Note that the resulting entry may not be marked present, though
 * non-present entries are always leafs (within a page
 * table/directory/etc, this will always visit all entries).
 */
static bool ptiter_succ(PTIter *it, Hpt hpt)
{
    int i, l, entsize;
    uint64 ent64;
    uint32 ent32;
    bool large;

    if (it->level < 0) {
        return false;
    } else if (!it->leaf) {
        /* Move to this entry's first child */
        it->level++;
        it->base[it->level] = it->pa;
        it->i[it->level] = 0;
    } else {
        /* Move forward and, if we hit the end of this level, up */
        while (++it->i[it->level] == it->layout->entries[it->level]) {
            if (it->level-- == 0) {
                /* We're out of page table */
                return false;
            }
        }
    }

    /* Read this entry */
    l = it->level;
    entsize = it->layout->entsize;
    hpt.lookup(it->base[l] + it->i[l] * entsize,
                             entsize == 4 ? (void *)&ent32 : (void *)&ent64,
                             entsize);
    /* Decode the entry */
    large = (it->pse && it->layout->pse[l] && (it->ent & Hpt::HPT_S));
    it->present = it->ent & Hpt::HPT_P;
    it->leaf = (large || !it->present || (l+1 == it->layout->levels));
    it->va = 0;
    for (i = 0; i <= l; i++) {
        it->va |= (uint64)it->i[i] << it->layout->shift[i];
    }
    it->pa = it->ent & (large ? 0x3ffffffffc000ULL : 0x3fffffffff000ULL);
    it->size = 1 << it->layout->shift[l];
    return true;
}

static void print_pte(uint64 addr,
                      uint64 pte,
                      uint64 mask)
{
#ifdef __x86_64__
    if (addr & (1ULL << 47)) {
        addr |= -1LL << 48;
    }
#endif
    Console::print("%016lx : %016lx %c%c%c%c%c%c%c%c\n",
                   addr,
                   pte & mask,
                   pte & Hpt::HPT_G ? 'G' : '-',
                   pte & Hpt::HPT_S ? 'P' : '-',
                   pte & Hpt::HPT_D ? 'D' : '-',
                   pte & Hpt::HPT_A ? 'A' : '-',
                   pte & Hpt::HPT_UC ? 'C' : '-',
                   pte & Hpt::HPT_PWT ? 'T' : '-',
                   pte & Hpt::HPT_U ? 'U' : '-',
                   pte & Hpt::HPT_W ? 'W' : '-');
}


/* Return true if the page tree rooted at iter is complete and
 * compatible with compat.  last will be filled with the last entry at
 * each level.  If false, does not change iter and last can be filled
 * with anything; if true, returns with iter at the next entry on the
 * same level, or the next parent entry if iter is on the last entry
 * of this level. */
static bool pg_complete(PTIter *root, const PTIter compat[], PTIter last[])
{
    PTIter iter = *root;

    if ((root->ent & 0xfff) != (compat[root->level].ent & 0xfff)) {
        return false;
    }

    last[root->level] = *root;
    ptiter_succ(&iter);
    if (!root->leaf) {
        /* Are all of the direct children of root complete? */
        while (iter.level == root->level + 1) {
            if (!pg_complete(&iter, compat, last)) {
                return false;
            }
        }
    }
    assert(iter.level <= root->level);
    assert(iter.level == root->level ?
           iter.i[iter.level] == root->i[iter.level] + 1 : 1);
    *root = iter;
    return true;
}

static char *pg_bits(uint64 ent)
{
    static char buf[32];
    Console::print(buf, "%c%c%c%c%c%c%c%c%c",
            /* TODO: Some of these change depending on level */
            ent & Hpt::HPT_G ? 'G' : '-',
            ent & Hpt::HPT_S ? 'S' : '-',
            ent & Hpt::HPT_D ? 'D' : '-',
            ent & Hpt::HPT_A ? 'A' : '-',
            ent & Hpt::HPT_UC ? 'C' : '-',
            ent & Hpt::HPT_PWT ? 'T' : '-',
            ent & Hpt::HPT_U ? 'U' : '-',
            ent & Hpt::HPT_W ? 'W' : '-',
            ent & Hpt::HPT_P ? 'P' : '-');
    return buf;
}

static void pg_print(PTIter *s, PTIter *l)
{
    int lev = s->level;
    char buf[128];
    char *pos = buf, *end = buf + sizeof(buf);

    /* VFN range */
    pos += Console::print("%*s[%0*lx-%0*lx] ", pos,
                   lev*2, "",
                   s->layout->vaw - 3, (uint64)s->va >> 12,
                   s->layout->vaw - 3, ((uint64)l->va + l->size - 1) >> 12);

    /* Slot */
    if (s->i[lev] == l->i[lev]) {
        pos += Console::print(pos, "%4s[%03x]    ",
                       s->layout->names[lev], s->i[lev]);
    } else {
        pos += Console::print(pos, "%4s[%03x-%03x]",
                       s->layout->names[lev], s->i[lev], l->i[lev]);
    }

    /* Flags */
    pos += Console::print(pos, " %s", pg_bits(s->ent));

    /* Range-compressed PFN's */
    if (s->leaf) {
        PTIter iter = *s;
        int i = 0;
        bool exhausted = false;
        while (!exhausted && i++ < 10) {
            uint64 pas = iter.pa, pae = iter.pa + iter.size;
            while (ptiter_succ(&iter) && iter.va <= l->va) {
                if (iter.level == s->level) {
                    if (iter.pa == pae) {
                        pae = iter.pa + iter.size;
                    } else {
                        goto print;
                    }
                }
            }
            exhausted = true;

print:
            if (pas >> 12 == (pae - 1) >> 12) {
                pos += Console::print(pos, end-pos, " %0*lx",
                                s->layout->paw - 3, (uint64)pas >> 12);
            } else {
                pos += Console::print(pos, end-pos, " %0*lx-%0*lx,
                                s->layout->paw - 3, (uint64)pas >> 12,
                                s->layout->paw - 3, (uint64)(pae - 1) >> 12);
            }
            pos = MIN(pos, end);
        }
    }

    /* Trim line to fit screen */
    if (pos - buf > 79) {
        strcpy(buf + 77, "..");
    }

    Console::print(mon, "%s\n", buf);
}

void pg_info(mword cr3)
{
    PTIter iter;

    if (!ptiter_init(cr3, &iter)) {
        return;
    }

    /* Header line */
    Console::print("%-*s %-13s %-10s %*s%s\n",
                   3 + 2 * (iter.layout->vaw-3), "VPN range",
                   "Entry", "Flags",
                   2*(iter.layout->levels-1), "", "Physical page");

    while (iter.level >= 0) {
        int i, startLevel, maxLevel;
        PTIter start[4], last[4], nlast[4];
        bool compressed = false;

        /* Skip to the next present entry */
        do { } while (!iter.present && ptiter_succ(&iter));
        if (iter.level < 0) {
            break;
        }

        /* Find a run of complete entries starting at iter and staying
         * on the same level. */
        startLevel = iter.level;
        memset(start, 0, sizeof(start));
        do {
            start[iter.level] = iter;
        } while (!iter.leaf && ptiter_succ(&iter));
        maxLevel = iter.level;
        iter = start[startLevel];
        while (iter.level == startLevel && pg_complete(&iter, start, nlast)) {
            compressed = true;
            memcpy(last, nlast, sizeof(last));
        }

        if (compressed) {
            /* We found a run we can show as a range spanning
             * [startLevel, maxLevel].  start stores the first entry
             * at each level and last stores the last entry. */
            for (i = startLevel; i <= maxLevel; i++) {
                pg_print(&start[i], &last[i]);
            }
        } else {
            /* No luck finding a range.  Iter hasn't moved. */
            pg_print(&iter, &iter);
            ptiter_succ(&iter);
        }
    }
}
