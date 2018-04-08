#include "malloc.h"

#include <string.h>

static bool is_my_mallloc_init = 0;

static Arena main_arena;

inline void ERROR_MSG(const char* msg)
{
    write(3,msg,strlen(msg));
    _exit(-1);
}
inline size_t GET_CHUNK_SIZE(Chunk* chunk)
{
    return (chunk->size >> 3) << 3;
}

inline size_t GET_REAL_SIZE(size_t size)
{
    return size & 7 ? ((size >> 3 << 3) + 8) : size; 
}
inline void* GET_USER_CHUNK(Chunk* p)
{
    return (void*)((void*)&(*p)+2*sizeof(size_t));
}

inline Chunk* GET_CHUNK(void* p)
{
    return (Chunk*)(p-sizeof(size_t)*2);
}

inline void SET_PRE_INUSE(Chunk*p,int flag)
{
    if(flag == 0)
    {
        p->pre_size = (p->pre_size>>1<<1);
    }
    if(flag == 1)
    {
        if(p->pre_size & 1)
        {
            return;
        }
        p->pre_size +=1;
    }
}

inline bool IS_CHUNK_MMAPED(Chunk* p)
{
    return (p->size&2);
}

inline void SET_MMAPED_FALG(Chunk* p,int flag)
{
    if(flag == 0)
    {
        if(IS_CHUNK_MMAPED(p))
        {
            p->size -= 2;
            return;
        }
    }
    if(flag == 1)
    {
        if(IS_CHUNK_MMAPED(p))
        {
            return;
        }
        p += 2;
    }
}

void my_malloc_init()
{
    main_arena.free_chunk_list = NULL;
    HeapMem* first_heap = (HeapMem*)mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE,
                  0, 0);
    if(first_heap == (HeapMem*)-1)
    {
        ERROR_MSG(strerror(errno));
    }
    main_arena.memory_arena_head = first_heap;
    main_arena.memory_arena_tail = first_heap;
    first_heap->last = (HeapMem*)&main_arena;
    first_heap->next = NULL;
    Chunk* first_top_chunk = (Chunk*)((void*)&(*first_heap) + sizeof(HeapMem));
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    main_arena.top_chunk = first_top_chunk;

}

void add_to_free_list(Chunk* p)
{
    if(main_arena.free_chunk_list == NULL)
    {
        main_arena.free_chunk_list = p;
        p->last = main_arena.free_chunk_list;
        p->next = NULL;
    }
    else
    {
        auto chunk_p = main_arena.free_chunk_list;
        while(chunk_p->next!=NULL)
        {
            chunk_p = chunk_p->next;
        }
        chunk_p->next = p;
        p->last = chunk_p;
        p->next = NULL;
    }

}

void unlink_from_free_list(Chunk* p)
{   
    Chunk* last = p->last;
    Chunk* next = p->next;
    if(next!=NULL)
    {
        next->last = last;
    }
    if(last!=NULL)
    {
        last->next = next;
    }
}

Chunk* try_free_list(size_t size)
{
    if(main_arena.free_chunk_list != NULL)
    {
        for(auto p = main_arena.free_chunk_list;p!=NULL;p=p->next)
        {
            if(GET_CHUNK_SIZE(p) >= size)
            {
                size_t new_size = GET_CHUNK_SIZE(p) - size;
                if(new_size > sizeof(Chunk))
                {
                    unlink_from_free_list(p);
                    Chunk* new_chunk = (Chunk*)((void*)&(*p) + size);
                    new_chunk->size = new_size;
                    new_chunk->pre_size = size;
                    SET_PRE_INUSE(new_chunk,1);
                   
                    add_to_free_list(new_chunk);
                    p->size = size;
                    return p;
                }
                else
                {
                    unlink_from_free_list(p);
                    return p; 
                }
            }
        }
    }
    return NULL;
}

Chunk* try_split_top_chunk(size_t size)
{
    if(size > main_arena.top_chunk->size)
    {
        return NULL;
    }
    Chunk* res = main_arena.top_chunk;

    main_arena.top_chunk = (Chunk*)((void*)&(*main_arena.top_chunk) + size);
    main_arena.top_chunk->size = res->size - size;
    res->size = size;
    
    return res;
}

void alloc_new_heap()
{
    add_to_free_list(main_arena.top_chunk);
    HeapMem* first_heap = (HeapMem*)mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE,
              0, 0);
    if(first_heap == (HeapMem*)-1)
    {
        ERROR_MSG(strerror(errno));
    }
    // main_arena.memory_arena_head = first_heap;
    auto p = main_arena.memory_arena_head;
    while(p->next!=NULL)
    {
        p = p->next;
    }
    p->next=first_heap;
    first_heap->last = p;
    first_heap->next = NULL;
    main_arena.memory_arena_tail = first_heap;
    
    Chunk* first_top_chunk = (Chunk*)((void*)&(*first_heap) + sizeof(HeapMem));
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    main_arena.top_chunk = first_top_chunk;
}

void* my_malloc(size_t size)
{

    if(size >> 63)
    {
        return NULL;
    }
    if(!is_my_mallloc_init)
    {
        my_malloc_init();
        is_my_mallloc_init = 1;
    }
    size = GET_REAL_SIZE(size) + 2*sizeof(size_t);
    if(size>getpagesize()-sizeof(HeapMem)-sizeof(Chunk))
    {
        Chunk* mmaped_chunk =  (Chunk*)mmap(NULL, size + sizeof(Chunk), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE,
              0, 0);
        mmaped_chunk->pre_size = 0;
        mmaped_chunk->size = size + sizeof(Chunk);
        SET_MMAPED_FALG(mmaped_chunk,1);
        return GET_USER_CHUNK(mmaped_chunk);
    }
    Chunk* res = NULL;
    if(res = try_free_list(size))
    {
        return GET_USER_CHUNK(res);
    }

    if(res = try_split_top_chunk(size))
    {
        return GET_USER_CHUNK(res);
    }

    alloc_new_heap();
    if(res = try_split_top_chunk(size))
    {
        return GET_USER_CHUNK(res);
    }

    return NULL;
}

void my_free(void* ptr)
{
    if(ptr == NULL)
    {
        return;
    }
    Chunk* p = GET_CHUNK(ptr);
    if(IS_CHUNK_MMAPED(p))
    {
        munmap(p,p->size);
        return;
    }

    add_to_free_list(p);

}