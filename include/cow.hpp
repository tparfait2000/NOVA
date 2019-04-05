/* 
 * File:   cow.hpp
 * Author: parfait
 *
 * Created on 13 novembre 2015, 22:09
 */
#pragma once

#include "memory.hpp"
#include "types.hpp"
#include "buddy.hpp"
#include "hip.hpp"
#include "vtlb.hpp"

class Cow {
private:
    static Spinlock cow_lock;

public:
    static uint32 frame_index_max;
    static uint32 elt_index_max;
    static bool max_displayed;

    struct cow_frame {
        Paddr phys_addr = {};
        uint32 index = {};
        bool used = false;
    };
    static struct cow_frame cow_frames[NB_COW_FRAME];

    struct cow_elt {
        mword page_addr_or_gpa = {}; // if VM, this will hold the gpa, else hold page addr
        Vtlb *vtlb_entry = {};
        Paddr old_phys = {};
        mword attr = {};
        struct cow_frame* new_phys[2];
        bool used = false;
        uint64 prev_tlb_val = {};
        struct cow_elt *next = {nullptr};
    };
    static struct cow_elt cow_list[NB_COW_ELT];

    enum Multiboot_Type {
        MULTIBOOT_MODULE = -2,
        MICROHYPERVISOR = -1,
        AVAILABLE_MEMORY = 1,
        RESERVED_MEMORY = 2,
        ACPI_RECLAIM_MEMORY = 3,
        ACPI_NVS_MEMORY = 4
    };

    Cow();
    //    Cow(const Cow& orig);
    virtual ~Cow();

    /**
     * @param elt_index
     * @return 
     */
    static bool get_cow_list_elt(uint32 & elt_index);
    static bool get_new_cow_frame(uint32 & frame_index);
    static void free_cow_frame(struct cow_frame * frame_ptr);

    static void free_cow_elt(cow_elt * cow);

    static bool get_new_cow_frame(cow_frame** frame_ptr);

    static bool get_cow_list_elt(cow_elt** cow_ptr);
    static bool subtitute(Paddr phys, cow_elt* cow, mword addr);
    static void initialize();

};