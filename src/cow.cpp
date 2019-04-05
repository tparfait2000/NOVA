/* 
 * File:   cow.cpp
 * Author: parfait
 * 
 * Created on 13 novembre 2015, 22:09
 */

#include "cow.hpp"
#include "memory.hpp"
#include "string.hpp"
#include "pd.hpp"

uint32 Cow::frame_index_max = 0;
uint32 Cow::elt_index_max = 0;
struct Cow::cow_elt Cow::cow_list[NB_COW_ELT];
struct Cow::cow_frame Cow::cow_frames[NB_COW_FRAME];

Spinlock Cow::cow_lock;

Cow::Cow() {
}

//Cow::Cow(const Cow& orig) {
//}

Cow::~Cow() {
}

/**
 * @param elt_index
 * @return 
 */
bool Cow::get_cow_list_elt(uint32 & elt_index) {
    for (uint32 i = 0; i < NB_COW_ELT; i++) {
        if (!cow_list[i].used) {
            elt_index = i;
            cow_list[i].used = true;
            return true;
        }
    }
    return false; //cow_list elt may be exhausted
}

bool Cow::get_new_cow_frame(uint32 & frame_index) {
    for (uint32 i = 0; i < NB_COW_FRAME; i++) {
        if (!cow_frames[i].used) {
            frame_index = i;
            cow_frames[i].used = true;
            return true;
        }
    }
    return false;
}

void Cow::free_cow_frame(struct cow_frame * frame_ptr) {
    frame_ptr->used = false;
}

void Cow::free_cow_elt(cow_elt * cow) {
    cow->old_phys = (~0ul); //0xffffffff; old_phys when set would always be differrent from 0xffffffff because pages are allocated at page boundary
    cow->page_addr_or_gpa = (~0ul); // 0xffffffff;
    cow->used = false;
    free_cow_frame(cow->new_phys[0]);
    free_cow_frame(cow->new_phys[1]);
}

bool Cow::get_new_cow_frame(cow_frame** frame_ptr) {
    uint32 frame_index = 0;
    if (!get_new_cow_frame(frame_index))
        return false;
    cow_frames[frame_index].used = true;
    if (frame_index > frame_index_max) {
        frame_index_max = frame_index;
    }
    *frame_ptr = &cow_frames[frame_index];
    //        if (Cpu::id != 0)
    //        Console::print("cpu: %2d  frame_index: %d", Cpu::id, frame_index);
    return true;
}

bool Cow::get_cow_list_elt(cow_elt** cow_ptr) {
    Lock_guard <Spinlock> guard(Cow::cow_lock);
    uint32 elt_index = 0;
    if (!get_cow_list_elt(elt_index)) return false;
    if (elt_index > elt_index_max) {
        elt_index_max = elt_index;
    }
    *cow_ptr = &cow_list[elt_index];
    return true;
}

bool Cow::subtitute(Paddr phys, cow_elt* cow, mword addr) {
    //        Lock_guard <Spinlock> guard(Cow::cow_lock);
    struct cow_frame *frame1, *frame2;
    if (!get_new_cow_frame(&frame1))
        return false;
    if (!get_new_cow_frame(&frame2))
        return false;
//    if (!max_displayed) {
//        Console::print("cpu: %2d  frame_index_max: %d  elt_index_max: %d", Cpu::id, frame_index_max, elt_index_max);
//        max_displayed = true;
//    }
    void *ptr = Hpt::remap_cow(Pd::kern.quota, frame1->phys_addr); //we only have 2^NB_COW_FRAME availlable, may be exhausted
    memcpy(ptr, reinterpret_cast<const void*> (addr), PAGE_SIZE);
    cow->new_phys[0] = frame1;
    ptr = Hpt::remap_cow(Pd::kern.quota, frame2->phys_addr); //we only have 2^NB_COW_FRAME availlable, may be exhausted
    memcpy(ptr, reinterpret_cast<const void*> (addr), PAGE_SIZE);
    cow->new_phys[1] = frame2;
    cow->old_phys = phys;

    return true;
}

void Cow::initialize() {
    // Allocate NB_COW_FRAME cow frames
    for (uint64 i = 0; i < NB_COW_FRAME; i++)
        cow_frames[i].phys_addr = Buddy::ptr_to_phys(Buddy::allocator.alloc(0, Pd::kern.quota, Buddy::FILL_0));
}

