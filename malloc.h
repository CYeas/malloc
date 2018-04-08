#ifndef UNTITLED_LIBRARY_H
#define UNTITLED_LIBRARY_H


#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" void* my_malloc(size_t);

extern "C" void my_free(void*);

struct Chunk
{
    size_t pre_size;  // the last one bit : is_pre_inuse 
    size_t size;      // the last two bit : is_mmaped is_inuse 
    // only use in free chunk
    Chunk* last;
    Chunk* next;
};


struct HeapMem
{
    HeapMem* last;
    HeapMem* next;
    // data
};

struct Arena
{
    HeapMem* memory_arena_head;
    HeapMem* memory_arena_tail;
    Chunk* top_chunk;
    Chunk* free_chunk_list;

};

#endif


