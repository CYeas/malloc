#ifndef UNTITLED_LIBRARY_H
#define UNTITLED_LIBRARY_H


#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>  

extern "C" void* my_malloc(size_t);

extern "C" void my_free(void*);

/**
 * 一个内存块单元描述结构
 */
struct Chunk
{
    size_t pre_size;  // the last two bit : cas_flag is_pre_inuse 
    size_t size;      // the last two bit : is_mmaped is_inuse 
    // only use in free chunk
    Chunk* last;//上一个chunk
    Chunk* next;//下一个chunk
};



struct HeapMem
{
    HeapMem* last;
    HeapMem* next;
    // data
};

/**
 * 维护从系统中获得的内存空间的总量和拆分链表
 */
struct Arena
{
    HeapMem* memory_arena_head;
    HeapMem* memory_arena_tail;
    Chunk* top_chunk;
    //Chunk* last_chunk_list;
    Chunk* free_chunk_list;
    int cas_flag = 0;
};

#endif

//#define IS_DEBUG 1

