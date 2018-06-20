#include "malloc.h"

#include <string.h>

#ifdef IS_DEBUG
#include <stdio.h>
#include <pthread.h>
#endif

void alloc_new_heap();

void unlink_from_free_list(Chunk *p);

void add_to_free_list(Chunk *p);

static int is_my_mallloc_init = 0;

static Arena main_arena;

static Chunk main_arena_fake_chunk;

static int free_cas = 0;
static int malloc_flag = 0;

#ifdef IS_DEBUG
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/**
打印错误信息
*/
inline void ERROR_MSG(const char *msg)
{
    write(2, msg, strlen(msg));
    _exit(-1);
}

/**
查询是否已经被cas标记，也即pre_size倒数第二位是否为1
*/
inline bool IS_CAS_FLAG(Chunk *p)
{
    return ((p->pre_size >> 2) & 1);
}

/**
置cas标记为1
*/
inline void SET_CAS_FLAG(Chunk *p)
{
    p->pre_size = p->pre_size | 2;
}

/**
解除cas标记，即将其置为0
*/
inline void RELEASE_CAS_FLAG(Chunk *p)
{
    SET_CAS_FLAG(p);
    p->pre_size = p->pre_size ^ 2;
}

/**
使用内联汇编cmpxchg进行原子操作
比较cas和预期的值，如果相同则置为new_value,属于原子操作
*/
inline bool FLAG_CAS(int old, int *flag, int new_value)
{

    __asm__ __volatile__(
        "lock cmpxchg %3,%1"
        : "=a"(old), "=m"(*(volatile int *)(flag))
        : "0"(flag), "r"(new_value));
    return flag;
}

/**
原子操作，写入更改ARENA的cas位
*/
inline bool ARENA_CAS(bool old, bool new_value)
{

    int tmp = main_arena.cas_flag;
    __asm__ __volatile__(
        "lock cmpxchg %3,%1"
        : "=a"(old), "=m"(*(volatile int *)(&tmp))
        : "0"(tmp), "r"(new_value));
    main_arena.cas_flag = tmp;
    return tmp;
}
/**
使用内联汇编cmpxchg进行原子操作
更新cas状态,属于原子操作
*/
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

/**
获取一个管理块的大小
*/
inline size_t GET_CHUNK_SIZE(Chunk *chunk)
{
    return (chunk->size >> 3) << 3;//先将cas信息位清为零
}

/**
获取真实的大小
*/
inline size_t GET_REAL_SIZE(size_t size)
{
    return size & 7 ? ((size >> 3 << 3) + 8) : size;
}
//获取给用户使用的块的地址
inline void *GET_USER_CHUNK(Chunk *p)
{
    while (!CAS(false, p, true))
        ;
    return (void *)((void *)&(*p) + 2 * sizeof(size_t));
}
/**
由指针地址获得描述信息
*/
inline Chunk *GET_CHUNK(void *p)
{
    return (Chunk *)(p - sizeof(size_t) * 2);
}
/**
获取页大小
*/
inline size_t PAGE_SIZE(size_t size)
{
    return size % getpagesize() == 0 ? size : (size / getpagesize() + getpagesize());
}
/**
设置前一个块的在使用辅助标志
*/
inline void SET_PRE_INUSE(Chunk *p, int flag)
{
    if (flag == 0)
    {
        p->pre_size = (p->pre_size >> 1 << 1);
    }
    if (flag == 1)
    {
        p->pre_size |= 1;
    }
}
/**
将块设为在使用
*/
inline void SET_CHUNK_INUSE(Chunk *p, int flag)
{
    if (flag == 0)
    {
        p->size = (p->size >> 1 << 1);
    }
    if (flag == 1)
    {
        p->size |= 1;
    }
}
/**
映射的标志位是否为1
*/
inline bool IS_CHUNK_MMAPED(Chunk *p)
{
    return (p->size & 2);
}
/**
设置映射的标志位
*/
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
/**
获取上一个块
*/
inline Chunk *GET_LAST_CHUNK(Chunk *p)
{
    return (Chunk *)((size_t)((void *)&(*p) - ((p->pre_size) >> 2 << 2)) >> 2 << 2);
}
/**
获取下一个块
*/
inline Chunk *GET_NEXT_CHUNK(Chunk *p)
{
    return (Chunk *)((size_t)((void *)&(*p) + p->size) >> 2 << 2);
}
//设置前一个块在使用
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
/**
前一个块是否被使用
*/
inline bool IS_PRE_INUSE(Chunk *p)
{
    return (p->pre_size & 1);
}
/**
后一个块是否被使用
*/
inline bool IS_NEXT_INUSE(Chunk *p)
{
    Chunk *next = GET_NEXT_CHUNK(p);
    return (next->size & 1);
}
/**
这个块是否在被使用
*/
inline bool IS_CHUNK_INUSE(Chunk *p)
{
    return (p->size & 1);
}

/**
初始化malloc
*/
void my_malloc_init()
{
    //将初始分配给用于管理的空间维护管理
    main_arena.free_chunk_list = &main_arena_fake_chunk;

    main_arena_fake_chunk.last = NULL;
    main_arena_fake_chunk.next = NULL;
    main_arena_fake_chunk.size = 0;
    main_arena_fake_chunk.pre_size = 0;

    //main_arena.last_chunk_list = NULL;
    //将分配的内存映射到系统空间，方便共享使用
    HeapMem *first_heap = (HeapMem *)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                          0, 0);
    if (first_heap == (HeapMem *)-1)
    {
    //没有分配到
        ERROR_MSG(strerror(errno));
    }
    
    main_arena.memory_arena_head = first_heap;
    main_arena.memory_arena_tail = first_heap;
    //第一个内存块
    first_heap->last = (HeapMem *)&main_arena;
    first_heap->next = NULL;
    //将内存快开始的部分偏移HeapMem的位置存放本块的chunck信息
    Chunk *first_top_chunk = (Chunk *)((void *)&(*first_heap) + sizeof(HeapMem));
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    //用main_arena的top_chunk维护chunck信息块链表
    main_arena.top_chunk = first_top_chunk;
}
/**
尝试将分开的内存快结合
*/
bool try_combine_chunk(Chunk *p)
{

    int flag = 0;
    auto save_p = p;
    if (p->size == 0)//块的size为零
    {
        return false;
    }
    if (p == main_arena.top_chunk)//已经是第一个块
    {
        return false;
    }

retry_combine_pre://与上一个伙伴合并
    p = save_p;
    while (p->pre_size != 0)
    {
        if (p->pre_size == 0)//如果前一个块的空间为0，则放弃
        {
            break;
        }
        if (IS_PRE_INUSE(p)) //如果前一个已经被使用，则放弃合并前一个
        {
            break;
        }
        Chunk *last = GET_LAST_CHUNK(p);//获取chunck
        unlink_from_free_list(last);//从空闲块链表种脱出
        if (!CAS(false, last, true))//如果此块在cas操作过程中
        {
            goto retry_combine_pre;//重新尝试
        }
        //int tmp = last->pre_size & 3;
        last->size = GET_CHUNK_SIZE(last) + GET_CHUNK_SIZE(p);//合并两个块的内存
        SET_CHUNK_INUSE(last, 0);//置零正在使用标志
        if ((size_t)GET_NEXT_CHUNK(last) % getpagesize() == 0){ // 如果下一个的大小刚好为一页（一块）
            SET_NEXT_CHUNK_PREUSE(last, 0); // 设置下一个块使用
        }
        //SET_PRE_INUSE(last,tmp);
        //last->pre_size = last->pre_size +
        RELEASE_CAS_FLAG(last);//解除cas锁
        p = last;
        flag = 1;
    }

retry_combine_next: //与下一个伙伴合并
    while (p->size != 0)
    {

        Chunk *next = GET_NEXT_CHUNK(p);// 取得下一个伙伴
        if ((size_t)(next) % getpagesize() == 0) //如果下一个块刚好是页结束
        {
            add_to_free_list(p); 将本块放入空闲链表中
            return true;
        }
        if (IS_CHUNK_INUSE(p)) //如果块被其他线程使用中
        {
            goto combine_end;// 跳到结尾
            //   return false;
        }
        if (next == main_arena.top_chunk) //如果下一个是管理空间的开始
        {
            if (!CAS(false, p, true))//cas重新尝试
            {
                goto retry_combine_next;
            }
            p->size = GET_CHUNK_SIZE(next) + GET_CHUNK_SIZE(p);
            SET_CHUNK_INUSE(p, 0);
            RELEASE_CAS_FLAG(p);

            while (!ARENA_CAS(false, true)) //直到cas解除
            {
            }
            main_arena.top_chunk = p;
            ARENA_CAS(true, false);
            //add_to_free_list(p);
            return true;
        }
        if (IS_CAS_FLAG(next)) //被cas加锁
        {
            goto retry_combine_next;//重新尝试
        }
        if (next->size == 0) //下一块的空间已经为零
        {
            break;
        }
        unlink_from_free_list(next); //从空闲块中脱出
        if (!CAS(false, p, true))
        {
            goto retry_combine_next;
        }
        p->size = GET_CHUNK_SIZE(next) + GET_CHUNK_SIZE(p);//将新块大小设置为两块之和
        SET_CHUNK_INUSE(p, 0);
        RELEASE_CAS_FLAG(p);
#ifdef IS_DEBUG
        //printf("combine add 0x%x to free list\n",p);
#endif
        //return true;
        flag = 1;
    }

combine_end://合并结束
    if (flag == 1)
    {
        add_to_free_list(p);//合并结束后将其加入到空闲链表中供继续使用
        return true;
    }

    return false;
}
/**
添加到空闲链表中
*/
void add_to_free_list(Chunk *p)
{
    // if(!IS_CHUNK_INUSE(p))
    // {
    //     return;
    // }
    
    //一些异常情况的处理
    if (p == NULL) //空指针
    {
        return;
    }
    if (p == main_arena.top_chunk)//是第一个块
    {
        return;
    }
    if (((size_t)p) % getpagesize() == 0) //已经是结束的块
    {
        ERROR_MSG("free chunk invaild\n");
    }

search_restart:
    if (main_arena.cas_flag) //检测如果上了cas锁，则回到重新尝试
    {
        goto search_restart;
    }
    auto chunk_p = main_arena.free_chunk_list; //空闲列表
    while (chunk_p->next != NULL) 
    {
        if (IS_CAS_FLAG(chunk_p))
        {
            goto search_restart; // 回头重新尝试
        }
        chunk_p = chunk_p->next; //循环一遍，直到所有块都已经解除cas
    }
    if (!CAS(false, chunk_p, true))
    {
        goto search_restart;
    }
    //插入链表
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
    RELEASE_CAS_FLAG(chunk_p); //解除cas flag
}

/**
从空闲块链表中脱出
*/
void unlink_from_free_list(Chunk *p)
{
//处理意外情况
    if (p == NULL)
    {
        return;
    }
    if (p == &main_arena_fake_chunk) //地址为空间开头
    {
        ERROR_MSG("memory down!\n");
    }
restart:
    Chunk *last = p->last;
    Chunk *next = p->next;

    if (next != NULL)
    {
        if (!CAS(false, next, true))//检测cas是否上锁
        {
            goto restart; //重新尝试
        }
    }

    if (last != NULL)
    {
        if (!CAS(false, last, true))//检测是否上cas锁
        {
            RELEASE_CAS_FLAG(next);//解除上一个的锁
            goto restart;//重新尝试
        }
    }
    //交叉链表前后，跳过本块，使块脱出
    if (next)
    {
        next->last = last;//
        RELEASE_CAS_FLAG(next);
    }

    if (last)
    {
        last->next = next;
        RELEASE_CAS_FLAG(last);
    }
}
/**
尝试从已有的空闲块中查找是否有合适的块予以使用
*/
Chunk *try_free_list(size_t size)
{

re_try:
    if (main_arena.free_chunk_list != NULL)//有空闲块
    {
        for (auto p = main_arena.free_chunk_list; p != NULL; p = p->next) //遍历查找
        {
            if (IS_CAS_FLAG(p))//如果加上了cas锁，重新尝试
            {
                goto re_try;
            }
            if (GET_CHUNK_SIZE(p) >= size) //块大小大于所需要的大小
            {
                unlink_from_free_list(p); //从空闲块表中脱出，即变为非空闲表
                size_t new_size = GET_CHUNK_SIZE(p) - size;
                if (new_size > sizeof(Chunk)) //还留有足够空间给块描述信息
                {
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
                else //如果不够描述信息的话
                {
                    SET_NEXT_CHUNK_PREUSE(p, 1);
                    SET_CHUNK_INUSE(p, 1);
                    return p;
                }
            }
        }
    }
    return NULL;
}
/**
尝试拆分块，当块大小大于所申请的内存的两倍时，尝试将块拆分成两块，详见报告开头原理部分
*/
Chunk *try_split_top_chunk(size_t size)
{
top_restart:
//排除异常情况
    if (main_arena.top_chunk == NULL) //首块为空
    {
        return NULL;
    }
    if (size > main_arena.top_chunk->size) //大于总的大小
    {
        return NULL;
    }

    Chunk *res = main_arena.top_chunk;

    if (IS_CAS_FLAG(res)) //有cas锁的话，重新尝试
    {
        goto top_restart;
    }
    size_t new_size = res->size - size; //调整后的新的大小

    if (new_size < sizeof(Chunk)) //新的大小无法存储块描述文件
    {
        //alloc_new_heap();
        //res->size += new_size;
        while (!ARENA_CAS(false, true))//直到cas解除
            ;
        main_arena.top_chunk = NULL;
        ARENA_CAS(true, false);
        SET_CHUNK_INUSE(res, 1);
        return res;
    }
    res->size = size;
try_main_arena:
    if (!CAS(false, main_arena.top_chunk, true)) //直到cas解除
    {
        goto try_main_arena;
    }

    if (!ARENA_CAS(false, true))
    {
        RELEASE_CAS_FLAG(main_arena.top_chunk);//解除首块操作的cas
        goto try_main_arena;//重试
    }

    main_arena.top_chunk = (Chunk *)((void *)&(*main_arena.top_chunk) + size);//调整所能使用的内存的偏移
    main_arena.top_chunk->size = new_size; //设置新的大小

    ARENA_CAS(true, false);
    RELEASE_CAS_FLAG(main_arena.top_chunk); //解除cas
    SET_NEXT_CHUNK_PREUSE(res, 1);
    SET_CHUNK_INUSE(res, 1);
    RELEASE_CAS_FLAG(res);
    return res;
}

/**
重新映射，分配新的堆内存
*/
void alloc_new_heap()
{
#ifdef IS_DEBUG
    static int page_count = 0;
    printf("page : %d\n", ++page_count);

#endif
    while (!ARENA_CAS(false, true))//直到cas被释放
        ;

    add_to_free_list(main_arena.top_chunk);将上一个链表加入free链表
    HeapMem *first_heap = (HeapMem *)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,0, 0);
    if (first_heap == (HeapMem *)-1) //分配失败
    {
        ERROR_MSG(strerror(errno));
    }
    // main_arena.memory_arena_head = first_heap;
    auto p = main_arena.memory_arena_head;//取出所维护的内存开头
    while (p->next != NULL) //取得链表最后一个块
    {
        p = p->next;
    }
    p->next = first_heap;//将新的内存加入到最后一个链表处
    first_heap->last = p;
    first_heap->next = NULL;
    main_arena.memory_arena_tail = first_heap; //将所管理的内存后移到新申请的地址

    Chunk *first_top_chunk = (Chunk *)((void *)&(*first_heap) + sizeof(HeapMem)); //为新内存分配新的块描述信息
    first_top_chunk->pre_size = 0;
    first_top_chunk->size = getpagesize() - sizeof(HeapMem);
    main_arena.top_chunk = first_top_chunk;
    ARENA_CAS(true, false);//解除cas锁定
}

//分配内存开始
void *my_malloc(size_t size)
{
malloc_start:
    if (size >> 63)//如果请求内存大于2^63，取消分配
    {
        return NULL;
    }
    if (!FLAG_CAS(0, &malloc_flag, 1))//判断是否正在被使用
    {
        goto malloc_start;//重新尝试
    }
    if (!is_my_mallloc_init)//如果未初始化malloc
    {
        is_my_mallloc_init = 1;//初始化第一阶段
        my_malloc_init();//进行初始化
        is_my_mallloc_init = 2;//初始化第二阶段
    }
    while (is_my_mallloc_init != 2)//初始化还没结束，则等待
    {
        usleep(1);
    }
    size = GET_REAL_SIZE(size) + 4 * sizeof(size_t);//计算实际块大小
    if (size > getpagesize() - sizeof(HeapMem) - sizeof(Chunk))//若一个页或者块容量不够
    {
        size_t real_size = PAGE_SIZE(size + sizeof(size_t) * 2);
        Chunk *mmaped_chunk = (Chunk *)mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                            0, 0);//重新映射足够的块
        if (mmaped_chunk == (Chunk *)-1)//没有映射成功
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
        malloc_flag = 0;
        return GET_USER_CHUNK(mmaped_chunk);//将获取到的空间传回
    }
    Chunk *res = NULL;
    if (res = try_free_list(size))//从已有的空闲内存中尝试分配
    {
#ifdef IS_DEBUG
        printf("malloc by free list\n");

#endif
        malloc_flag = 0;
        return GET_USER_CHUNK(res);
    }

    if (res = try_split_top_chunk(size))//如果可以进行空闲块的拆分使用
    {
#ifdef IS_DEBUG
        printf("malloc by split chunk\n");

#endif
        malloc_flag = 0;
        return GET_USER_CHUNK(res);
    }

    alloc_new_heap();//依然不够使用，则分配新的空间以管理并使用
    if (res = try_split_top_chunk(size))
    {
#ifdef IS_DEBUG
        printf("malloc by alloc and slpit chunk\n");

#endif
        malloc_flag = 0;
        return GET_USER_CHUNK(res);
    }
    malloc_flag = 0;
    return NULL;//默认无法分配
}
/**
释放内存
*/
void my_free(void *ptr)
{
free_start:
    if (ptr == NULL)//如果是空指针
    {
        return;
    }

    if (!FLAG_CAS(0, &free_cas, 1))//如果正在被使用
    {
        goto free_start;//重新尝试
    }

    Chunk *p = GET_CHUNK(ptr);//获取指针所对应的块描述信息

#ifdef IS_DEBUG
    if ((unsigned long long)p & 0x7)
    {
        printf("error : %p\n", ptr);
        ERROR_MSG("");
    }
#endif
    if (IS_CHUNK_MMAPED(p))//块是由映射而来的
    {
        munmap(p, GET_CHUNK_SIZE(p));//解除映射
        free_cas = 0;//cas清0
        return;
    }
    if (!IS_CHUNK_INUSE(p))
    {
        ERROR_MSG("double free\n");
    }
    RELEASE_CAS_FLAG(p);//将cas的标志释放
    if (try_combine_chunk(p))//尝试将临近空闲块合并
    {
        free_cas = 0;
        return;
    }

    add_to_free_list(p);//将释放完的块加入到空闲链表中
    free_cas = 0;
#ifdef IS_DEBUG
    //printf("free add 0x%x to free list\n",p);
    int i = 0;
    for (auto pointer = main_arena.free_chunk_list; pointer != NULL; pointer = pointer->next, i++)
    {
    }
    printf("free list count : %d\n", i);

#endif
}