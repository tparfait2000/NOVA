/*
 * String Functions
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

#pragma once

#include "compiler.hpp"
#include "types.hpp"
#include "console.hpp"

extern "C" NONNULL
inline void *memcpy(void *dst, const void *src, size_t n) {
    const char *s;
    char *d;

    s = reinterpret_cast<const char*> (src);
    d = reinterpret_cast<char*> (dst);
    if (s < d && s + n > d) {
        s += n;
        d += n;
        if ((mword) s % 4 == 0 && (mword) d % 4 == 0 && n % 4 == 0)
            asm volatile("std; rep movsl\n"
                        ::"D" (d - 4), "S" (s - 4), "c" (n / 4) : "cc", "memory");
        else
            asm volatile("std; rep movsb\n"
                        ::"D" (d - 1), "S" (s - 1), "c" (n) : "cc", "memory");
        // Some versions of GCC rely on DF being clear
        asm volatile("cld" :: : "cc");
    } else {
        if ((mword) s % 4 == 0 && (mword) d % 4 == 0 && n % 4 == 0)
            asm volatile("cld; rep movsl\n"
                        ::"D" (d), "S" (s), "c" (n / 4) : "cc", "memory");
        else
            asm volatile("cld; rep movsb\n"
                        ::"D" (d), "S" (s), "c" (n) : "cc", "memory");
    }
    return dst;
}

extern "C" NONNULL
inline void copy_string(char *target, char *source) {
    uint32 length = 1;
    while (*source && length < str_max_length) {
        *target = *source;
        source++;
        target++;
        length++;
    }
    *target = '\0';
}

//extern "C" NONNULL
//inline void *memcpy(void *d, void const *s, size_t n) {
//    mword dummy;
//    asm volatile ("rep; movsb"
//                : "=D" (dummy), "+S" (s), "+c" (n)
//                : "0" (d)
//                : "memory");
//    return d;
//}

extern "C" NONNULL
inline void *memset(void *d, int c, size_t n) {
    mword dummy;
    asm volatile ("rep; stosb"
                : "=D" (dummy), "+c" (n)
                : "0" (d), "a" (c)
                : "memory");
    return d;
}

extern "C" NONNULL
inline int strcmp(char const *s1, char const *s2) {
    while (*s1 && *s1 == *s2)
        s1++, s2++;

    return *s1 - *s2;
}

extern "C" NONNULL
inline bool strmatch (char const *s1, char const *s2, size_t n)
{
    if (!n) return false;

    while (*s1 && *s1 == *s2 && n)
        s1++, s2++, n--;

    return n == 0;
}

/**
 * fonction a n'utiliser que pour comparer des tailles multiples de 4 et page aligned ex: 4ko
 * @param s1
 * @param s2
 * @param len
 * @return 
 */
extern "C" NONNULL
inline int memcmp(const void *s1, const void *s2, size_t len) {
    len /=4;
    int diff = 0;
    asm volatile ("repe; cmpsl; movl %%ecx, %0;"
                : "=qm" (diff), "+D" (s1), "+S" (s2), "+c" (len));
    return diff;
}

extern "C" NONNULL
/*
 It does not work
 */
inline void order_instruction(mword instr, char *buffer ) {
    int size = sizeof(mword);
    Console::sprint(buffer, "%lx ", instr); 
    char *p1 = buffer, *p2 = buffer + size -1;
    while(p1 < p2){
        char tmp = *p1;
        *p1++ = *p2;
        *p2-- = tmp;
    }
    
}

