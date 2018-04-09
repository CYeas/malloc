#include "malloc.h"

#include <string.h>

#ifdef IS_DEBUG
#include <stdio.h>
#endif


void alloc_new_heap();

void unlink_from_free_list(Chunk* p);

void add_to_free_list(Chunk* p);

static bool is_my_mallloc_init = 0;

static Arena main_arena;

static Chunk main_arena_fake_chunk;

inline void ERROR_MSG(const char* msg)
{
    write(2,msg,strlen(msg));
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

inline size_t PAGE_SIZE(size_t size)
{
    return size % getpagesize() == 0? size: (size/getpagesize() + getpagesize());
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

inline void SET_CHUNK_INUSE(Chunk*p,int flag)
{
    if(flag == 0)
    {
        p->size = (p->size>>1<<1);
    }
    if(flag == 1)
    {
        if(p->size & 1)
        {
            return;
        }
        p->size +=1;
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
        p->size += 2;
    }
}

inline Chunk* GET_LAST_CHUNK(Chunk *p)
{
    return (Chunk*)((size_t)((void*)&(*p)-p->pre_size)>>1<<1);
}

inline Chunk* GET_NEXT_CHUNK(Chunk*p)
{
    return (Chunk*)((size_t)((void*)&(*p)+p->size)>>2<<2);
}

inline void SET_NEXT_CHUNK_PREUSE(Chunk* p,int flag)
{
    Chunk* next = GET_NEXT_CHUNK(p);
    if(((size_t)next) % getpagesize() == 0)
    {
        return;
    }
    
    next->pre_size = p->size;
    SET_PRE_INUSE(next,1);
}
inline bool IS_PRE_INUSE(Chunk* p)
{
    return (p->pre_size & 1);
}
inline bool IS_NEXT_INUSE(Chunk* p)
{
    Chunk* next = GET_NEXT_CHUNK(p);
    return (next->size & 1);
}

inline bool IS_CHUNK_INUSE(Chunk* p)
{
    return (p->size&1);
}

void my_malloc_init()
{
    main_arena.free_chunk_list = &main_arena_fake_chunk;

    main_arena_fake_chunk.last = NULL;
    main_arena_fake_chunk.next = NULL;
    main_arena_fake_chunk.size = 0;
    main_arena_fake_chunk.pre_size = 0;

    //main_arena.last_chunk_list = NULL;
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

bool try_combine_chunk(Chunk* p)
{
    int flag = 0;
    if(p->pre_size==0)
    {
        return false;
    }
    if(p==main_arena.top_chunk)
    {
        return false;
    }
    while(!IS_PRE_INUSE(p))
    {
        if(p->pre_size==0)
        {
            break;
        }
        Chunk* last = GET_LAST_CHUNK(p);
        unlink_from_free_list(last);
        last->size = last->size + p->size;
        SET_CHUNK_INUSE(last,0);
        SET_NEXT_CHUNK_PREUSE(last,0);
        //add_to_free_list(last);
        //return true;
        p = last;
        flag = 1;
    }
   
    while(!IS_NEXT_INUSE(p))
    {
       
        Chunk* next = GET_NEXT_CHUNK(p);
        if((size_t)(next) % getpagesize() == 0)
        {
            return false;
        }
        if(next == main_arena.top_chunk)
        {
            p->size = p->size + next->size;   
            main_arena.top_chunk = p;
            //add_to_free_list(p);
            return true;
        }
        if(next->size == 0)
        {
            break;
        }
        unlink_from_free_list(next);
        p->size = p->size + next->size;
        #ifdef IS_DEBUG
        //printf("combine add 0x%x to free list\n",p);
        #endif
        
        //return true;
        flag = 1;
    }
    if(flag == 1)
    {
        add_to_free_list(p);
        return true;
    }

    return false;
    
}

void add_to_free_list(Chunk* p)
{
    // if(!IS_CHUNK_INUSE(p))
    // {
    //     return;
    // }
    if(p == NULL)
    {
        return;
    }
    if(p == main_arena.top_chunk)
    {
        return;
    }
    if(((size_t)p) % getpagesize() == 0)
    {
        ERROR_MSG("free chunk invaild\n");
    }
    // if(main_arena.free_chunk_list->last == NULL)
    // {
    //     main_arena.free_chunk_list->next = p;
    //     main_arena.free_chunk_list->last = p;
    //     p->last = main_arena.free_chunk_list->next;
    //     p->next = NULL;
    // }
    // else
    
    auto chunk_p = main_arena.free_chunk_list;
    while(chunk_p->next!=NULL)
    {
            
        chunk_p = chunk_p->next;
    }
    chunk_p->next = p;
    p->last = chunk_p;
    
    

    #ifdef IS_DEBUG
    if(p->last == p)
    {
        ERROR_MSG("add error\n");
    }
    #endif
    
    SET_NEXT_CHUNK_PREUSE(p,0);
    
    SET_CHUNK_INUSE(p,0);
    p->next = NULL;
}

void unlink_from_free_list(Chunk* p)
{   
    if(p == NULL)
    {
        return;
    }
    if(p == &main_arena_fake_chunk)
    {
        ERROR_MSG("memory down!\n");
    }
    Chunk* last = p->last;
    Chunk* next = p->next;
    // if(p==main_arena.free_chunk_list)
    // {
    //     main_arena.free_chunk_list = next;
    //     //main_arena.free_chunk_list = next;
    //     if(next!=NULL)
    //     {
    //         next->last = main_arena.free_chunk_list;
    //     }
    //     return;
    // }
    
    if(next!=NULL)
    {
        next->last = last;
    }
    
    if(last != NULL)
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
                    new_chunk->size = p->size - size;
                    new_chunk->pre_size = size;
                    
                    //SET_PRE_INUSE(new_chunk,1);

                    add_to_free_list(new_chunk);
                    p->size = size;
                    SET_CHUNK_INUSE(p,1);
                    SET_NEXT_CHUNK_PREUSE(p,1);
                    return p;
                }
                else
                {
                    SET_NEXT_CHUNK_PREUSE(p,1);
                    
                    unlink_from_free_list(p);
                    SET_CHUNK_INUSE(p,1);
                    return p; 
                }
            }
        }
    }
    return NULL;
}

Chunk* try_split_top_chunk(size_t size)
{
    if(main_arena.top_chunk == NULL)
    {
        return NULL;
    }
    if(size > main_arena.top_chunk->size)
    {
        return NULL;
    }
    Chunk* res = main_arena.top_chunk;

    main_arena.top_chunk = (Chunk*)((void*)&(*main_arena.top_chunk) + size);
    size_t new_size = res->size - size;
    if(new_size<sizeof(Chunk))
    {
        //alloc_new_heap();
        main_arena.top_chunk = NULL;
        SET_CHUNK_INUSE(res,1);
        
        return res;
    }
    main_arena.top_chunk->size = res->size - size;
    res->size = size;
    SET_NEXT_CHUNK_PREUSE(res,1);
    SET_CHUNK_INUSE(res,1);
    return res;
}


void alloc_new_heap()
{
    #ifdef IS_DEBUG
    static int page_count = 0;
    printf("page : %d\n",++page_count);

    #endif
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
    size = GET_REAL_SIZE(size) + 3*sizeof(size_t);
    if(size > getpagesize()-sizeof(HeapMem)-sizeof(Chunk))
    {
        size_t real_size = PAGE_SIZE(size + sizeof(size_t)*2);
        Chunk* mmaped_chunk =  (Chunk*)mmap(NULL, real_size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE,
              0, 0);
        if(mmaped_chunk == (Chunk*)-1)
        {
            ERROR_MSG(strerror(errno));
        }
        mmaped_chunk->pre_size = 0;
        mmaped_chunk->size = real_size;
        SET_MMAPED_FALG(mmaped_chunk,1);
        SET_CHUNK_INUSE(mmaped_chunk,1);
        #ifdef IS_DEBUG
        printf("malloc by mmap\n");
        
        #endif
        return GET_USER_CHUNK(mmaped_chunk);
    }
    Chunk* res = NULL;
    if(res = try_free_list(size))
    {
        #ifdef IS_DEBUG
        printf("malloc by free list\n");
        
        #endif
        return GET_USER_CHUNK(res);
    }

    if(res = try_split_top_chunk(size))
    {
        #ifdef IS_DEBUG
        printf("malloc by split chunk\n");
        
        #endif
        return GET_USER_CHUNK(res);
    }

    alloc_new_heap();
    if(res = try_split_top_chunk(size))
    {
        #ifdef IS_DEBUG
        printf("malloc by alloc and slpit chunk\n");
        
        #endif
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
        munmap(p,GET_CHUNK_SIZE(p));
        return;
    }
    if(!IS_CHUNK_INUSE(p))
    {
        ERROR_MSG("double free\n");
    }
    if(try_combine_chunk(p))
    {
        return;
    }

    add_to_free_list(p);
    #ifdef IS_DEBUG
    //printf("free add 0x%x to free list\n",p);
    int i=0;
    for(auto pointer=main_arena.free_chunk_list;pointer!=NULL;pointer=pointer->next,i++)
    {

    }
    printf("free list count : %d\n",i);

    #endif

}