#include "malloc.h"

#include <string.h>

#ifdef IS_DEBUG
#include <stdio.h>
#endif

void alloc_new_heap();

void unlink_from_free_list(Chunk *p);

void add_to_free_list(Chunk *p);

static int is_my_mallloc_init = 0;

static Arena main_arena;

static Chunk main_arena_fake_chunk;

inline void ERROR_MSG(const char *msg)
{
    write(2, msg, strlen(msg));
    _exit(-1);
}

inline bool IS_CAS_FLAG(Chunk *p)
{
    return ((p->pre_size >> 1) & 1);
}
inline void SET_CAS_FLAG(Chunk *p)
{
    p->pre_size = p->pre_size | 2;
}
inline void RELEASE_CAS_FLAG(Chunk *p)
{
    SET_CAS_FLAG(p);
    p->pre_size = p->pre_size ^ 2;
}

inline bool CAS(bool old, Chunk *p, bool new_value)
{

    bool tmp = IS_CAS_FLAG(p);
    __asm__ __volatile__(
        "lock cmpxchg %3,%1"
        : "=a"(old), "=m"(*(volatile bool *)(&tmp))
        : "0"(tmp), "r"(new_value));
    if (tmp)
    {
        SET_CAS_FLAG(p);
    }
    else
    {
        RELEASE_CAS_FLAG(p);
    }
    return tmp;
}

inline size_t GET_CHUNK_SIZE(Chunk *chunk)
{
    return (chunk->size >> 3) << 3;
}

inline size_t GET_REAL_SIZE(size_t size)
{
    return size & 7 ? ((size >> 3 << 3) + 8) : size;
}
inline void *GET_USER_CHUNK(Chunk *p)
{
    return (void *)((void *)&(*p) + 2 * sizeof(size_t));
}

inline Chunk *GET_CHUNK(void *p)
{
    return (Chunk *)(p - sizeof(size_t) * 2);
}

inline size_t PAGE_SIZE(size_t size)
{
    return size % getpagesize() == 0 ? size : (size / getpagesize() + getpagesize());
}

inline void SET_PRE_INUSE(Chunk *p, int flag)
{
    if (flag == 0)
    {
        p->pre_size = (p->pre_size >> 1 << 1);
    }
    if (flag == 1)
    {
        if (p->pre_size & 1)
        {
            return;
        }
        p->pre_size += 1;
    }
}

inline void SET_CHUNK_INUSE(Chunk *p, int flag)
{
    if (flag == 0)
    {
        p->size = (p->size >> 1 << 1);
    }
    if (flag == 1)
    {
        if (p->size & 1)
        {
            return;
        }
        p->size += 1;
    }
}

inline bool IS_CHUNK_MMAPED(Chunk *p)
{
    return (p->size & 2);
}

inline void SET_MMAPED_FALG(Chunk *p, int flag)
{
    if (flag == 0)
    {
        if (IS_CHUNK_MMAPED(p))
        {
            p->size -= 2;
            return;
        }
    }
    if (flag == 1)
    {
        if (IS_CHUNK_MMAPED(p))
        {
            return;
        }
        p->size += 2;
    }
}

inline Chunk *GET_LAST_CHUNK(Chunk *p)
{
    return (Chunk *)((size_t)((void *)&(*p) - ((p->pre_size) >> 2 << 2)) >> 2 << 2);
}

inline Chunk *GET_NEXT_CHUNK(Chunk *p)
{
    return (Chunk *)((size_t)((void *)&(*p) + p->size) >> 2 << 2);
}

inline void SET_NEXT_CHUNK_PREUSE(Chunk *p, int flag)
{
    Chunk *next = GET_NEXT_CHUNK(p);
    if (((size_t)next) % getpagesize() == 0)
    {
        return;
    }

    next->pre_size = p->size;
    SET_PRE_INUSE(next, 1);
}
inline bool IS_PRE_INUSE(Chunk *p)
{
    return (p->pre_size & 1);
}
inline bool IS_NEXT_INUSE(Chunk *p)
{
    Chunk *next = GET_NEXT_CHUNK(p);
    return (next->size & 1);
}

inline bool IS_CHUNK_INUSE(Chunk *p)
{
    return (p->size & 1);
}

void my_malloc_init()
{
    main_arena.free_chunk_list = &main_arena_fake_chunk;

    main_arena_fake_chunk.last = NULL;
    main_arena_fake_chunk.next = NULL;
    main_arena_fake_chunk.size = 0;
    main_arena_fake_chunk.pre_size = 0;

    //main_arena.last_chunk_list = NULL;
    HeapMem *first_heap = (HeapMem *)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                          0, 0);
    if (first_heap == (HeapMem *)-1)
    {
        ERROR_MSG(strerror(errno));
    }
    main_arena.memory_arena_head = first_heap;
    main_arena.memory_arena_tail = first_heap;
    first_heap->last = (HeapMem *)&main_arena;
    first_heap->next = NULL;
    Chunk *first_top_chunk = (Chunk *)((void *)&(*first_heap) + sizeof(HeapMem));
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    main_arena.top_chunk = first_top_chunk;
}

bool try_combine_chunk(Chunk *p)
{
    int flag = 0;
    auto save_p = p;
    if (p->size == 0)
    {
        return false;
    }
    if (p == main_arena.top_chunk)
    {
        return false;
    }

retry_combine_pre:
    p = save_p;
    while (!IS_PRE_INUSE(p))
    {
        if (p->pre_size == 0)
        {
            break;
        }
        Chunk *last = GET_LAST_CHUNK(p);
        unlink_from_free_list(last);
        if (!CAS(false, last, true))
        {
            goto retry_combine_pre;
        }
        last->size = GET_CHUNK_SIZE(last) + GET_CHUNK_SIZE(p);
        SET_CHUNK_INUSE(last, 0);
        SET_NEXT_CHUNK_PREUSE(last, 0);
        RELEASE_CAS_FLAG(last);
        p = last;
        flag = 1;
    }

retry_combine_next:
    while (!IS_NEXT_INUSE(p))
    {

        Chunk *next = GET_NEXT_CHUNK(p);
        if ((size_t)(next) % getpagesize() == 0)
        {
            return false;
        }
        if (next == main_arena.top_chunk)
        {
            if (!CAS(false, p, true))
            {
                goto retry_combine_next;
            }
            p->size = GET_CHUNK_SIZE(next) + GET_CHUNK_SIZE(p);
            SET_CHUNK_INUSE(p, 0);
            RELEASE_CAS_FLAG(p);
            main_arena.top_chunk = p;
            //add_to_free_list(p);
            return true;
        }
        if (next->size == 0)
        {
            break;
        }
        unlink_from_free_list(next);
        if (!CAS(false, p, true))
        {
            goto retry_combine_next;
        }
        p->size = GET_CHUNK_SIZE(next) + GET_CHUNK_SIZE(p);
        SET_CHUNK_INUSE(p, 0);
        RELEASE_CAS_FLAG(p);
#ifdef IS_DEBUG
        //printf("combine add 0x%x to free list\n",p);
#endif
        //return true;
        flag = 1;
    }
    if (flag == 1)
    {
        add_to_free_list(p);
        return true;
    }

    return false;
}

void add_to_free_list(Chunk *p)
{
    // if(!IS_CHUNK_INUSE(p))
    // {
    //     return;
    // }
    if (p == NULL)
    {
        return;
    }
    if (p == main_arena.top_chunk)
    {
        return;
    }
    if (((size_t)p) % getpagesize() == 0)
    {
        ERROR_MSG("free chunk invaild\n");
    }

search_restart:
    auto chunk_p = main_arena.free_chunk_list;
    while (chunk_p->next != NULL)
    {
        if (IS_CAS_FLAG(chunk_p))
        {
            goto search_restart;
        }
        chunk_p = chunk_p->next;
    }
    if (!CAS(false, chunk_p, true))
    {
        goto search_restart;
    }
    p->next = NULL;
    p->last = chunk_p;
    chunk_p->next = p;

#ifdef IS_DEBUG
    if (p->last == p)
    {
        ERROR_MSG("add error\n");
    }
#endif

    SET_NEXT_CHUNK_PREUSE(p, 0);

    SET_CHUNK_INUSE(p, 0);
    RELEASE_CAS_FLAG(chunk_p);
}

void unlink_from_free_list(Chunk *p)
{
    if (p == NULL)
    {
        return;
    }
    if (p == &main_arena_fake_chunk)
    {
        ERROR_MSG("memory down!\n");
    }
restart:
    Chunk *last = p->last;
    Chunk *next = p->next;

    if (next != NULL)
    {
        if (!CAS(false, next, true))
        {
            goto restart;
        }
    }

    if (last != NULL)
    {
        if (!CAS(false, last, true))
        {
            RELEASE_CAS_FLAG(next);
            goto restart;
        }
    }
    if (next)
    {
        next->last = last;
        RELEASE_CAS_FLAG(next);
    }

    if (last)
    {
        last->next = next;
        RELEASE_CAS_FLAG(last);
    }
}

Chunk *try_free_list(size_t size)
{
re_try:
    if (main_arena.free_chunk_list != NULL)
    {
        for (auto p = main_arena.free_chunk_list; p != NULL; p = p->next)
        {
            if (IS_CAS_FLAG(p))
            {
                goto re_try;
            }
            if (GET_CHUNK_SIZE(p) >= size)
            {
                size_t new_size = GET_CHUNK_SIZE(p) - size;
                if (new_size > sizeof(Chunk))
                {
                    unlink_from_free_list(p);
                    Chunk *new_chunk = (Chunk *)((void *)&(*p) + size);
                    new_chunk->size = GET_CHUNK_SIZE(p) - size;
                    new_chunk->pre_size = size;
                    //SET_PRE_INUSE(new_chunk,1);
                    add_to_free_list(new_chunk);
                    p->size = size;
                    SET_CHUNK_INUSE(p, 1);
                    SET_NEXT_CHUNK_PREUSE(p, 1);
                    return p;
                }
                else
                {
                    unlink_from_free_list(p);
                    SET_NEXT_CHUNK_PREUSE(p, 1);
                    SET_CHUNK_INUSE(p, 1);
                    return p;
                }
            }
        }
    }
    return NULL;
}

Chunk *try_split_top_chunk(size_t size)
{
top_restart:

    if (main_arena.top_chunk == NULL)
    {
        return NULL;
    }
    if (size > main_arena.top_chunk->size)
    {
        return NULL;
    }

    Chunk *res = main_arena.top_chunk;

    if (!CAS(false, res, true))
    {
        goto top_restart;
    }
    size_t new_size = res->size - size;
    if (new_size < sizeof(Chunk))
    {
        //alloc_new_heap();
        main_arena.top_chunk = NULL;
        SET_CHUNK_INUSE(res, 1);
        return res;
    }
    res->size = size;
    ((Chunk *)((void *)&(*main_arena.top_chunk) + size))->size = main_arena.top_chunk->size - size;
    main_arena.top_chunk = (Chunk *)((void *)&(*main_arena.top_chunk) + size);
    SET_NEXT_CHUNK_PREUSE(res, 1);
    SET_CHUNK_INUSE(res, 1);
    RELEASE_CAS_FLAG(res);
    return res;
}

void alloc_new_heap()
{
#ifdef IS_DEBUG
    static int page_count = 0;
    printf("page : %d\n", ++page_count);

#endif
    add_to_free_list(main_arena.top_chunk);
    HeapMem *first_heap = (HeapMem *)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                          0, 0);
    if (first_heap == (HeapMem *)-1)
    {
        ERROR_MSG(strerror(errno));
    }
    // main_arena.memory_arena_head = first_heap;
    auto p = main_arena.memory_arena_head;
    while (p->next != NULL)
    {
        p = p->next;
    }
    p->next = first_heap;
    first_heap->last = p;
    first_heap->next = NULL;
    main_arena.memory_arena_tail = first_heap;

    Chunk *first_top_chunk = (Chunk *)((void *)&(*first_heap) + sizeof(HeapMem));
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    main_arena.top_chunk = first_top_chunk;
}

void *my_malloc(size_t size)
{

    if (size >> 63)
    {
        return NULL;
    }
    if (!is_my_mallloc_init)
    {
        is_my_mallloc_init = 1;
        my_malloc_init();
        is_my_mallloc_init = 2;
    }
    while (is_my_mallloc_init != 2)
    {
        usleep(1);
    }
    size = GET_REAL_SIZE(size) + 4 * sizeof(size_t);
    if (size > getpagesize() - sizeof(HeapMem) - sizeof(Chunk))
    {
        size_t real_size = PAGE_SIZE(size + sizeof(size_t) * 2);
        Chunk *mmaped_chunk = (Chunk *)mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                            0, 0);
        if (mmaped_chunk == (Chunk *)-1)
        {
            ERROR_MSG(strerror(errno));
        }
        mmaped_chunk->pre_size = 0;
        mmaped_chunk->size = real_size;
        SET_MMAPED_FALG(mmaped_chunk, 1);
        SET_CHUNK_INUSE(mmaped_chunk, 1);
#ifdef IS_DEBUG
        printf("malloc by mmap\n");

#endif
        return GET_USER_CHUNK(mmaped_chunk);
    }
    Chunk *res = NULL;
    if (res = try_free_list(size))
    {
#ifdef IS_DEBUG
        printf("malloc by free list\n");

#endif
        return GET_USER_CHUNK(res);
    }

    if (res = try_split_top_chunk(size))
    {
#ifdef IS_DEBUG
        printf("malloc by split chunk\n");

#endif
        return GET_USER_CHUNK(res);
    }

    alloc_new_heap();
    if (res = try_split_top_chunk(size))
    {
#ifdef IS_DEBUG
        printf("malloc by alloc and slpit chunk\n");

#endif
        return GET_USER_CHUNK(res);
    }

    return NULL;
}

void my_free(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    Chunk *p = GET_CHUNK(ptr);
    if (IS_CHUNK_MMAPED(p))
    {
        munmap(p, GET_CHUNK_SIZE(p));
        return;
    }
    if (!IS_CHUNK_INUSE(p))
    {
        ERROR_MSG("double free\n");
    }
    if (try_combine_chunk(p))
    {
        return;
    }

    add_to_free_list(p);
#ifdef IS_DEBUG
    //printf("free add 0x%x to free list\n",p);
    int i = 0;
    for (auto pointer = main_arena.free_chunk_list; pointer != NULL; pointer = pointer->next, i++)
    {
    }
    printf("free list count : %d\n", i);

#endif
}