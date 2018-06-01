//
// Created by pzhxbz on 4/3/18.
//

#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <err.h>
#include <pthread.h>

#define TEST_THREAD_NUM 64

typedef void *(*my_malloc_ptr)(size_t);
typedef void (*my_free_ptr)(void *);

my_malloc_ptr malloc_func;
my_free_ptr free_func;

char *test_data[2048];

pthread_t pids[TEST_THREAD_NUM];

void *thread_test(void *ptr)
{
    int num = (int)ptr;
    for (int i = 0; i < num; i++)
    {
        void *data = malloc_func(rand() % getpagesize());
        free_func(data);
    }
}

void test()
{
    char *data; // = (char*)malloc_func(100);
    memset(test_data, 'a', 2048);

    //unsigned int seed = (unsigned int)time(NULL);
    unsigned int seed = 1527836216;
    printf("seed : %d\n", seed);

    srand(seed);
    int count = rand()%100;
    int j=0;
    char* datas[512]={0};
    for (int i = 0; i < 512; i++)
    {

        size_t size = rand() % getpagesize();
        printf("%d : size : %d ", i, size);
        data = (char *)malloc_func(size);
        printf("addr : %p \n", data);
        datas[i] = data;
        //memcpy(data, test_data, size > 2047 ? 2017 : size);
        if(rand()%3==0)
        {
            free_func(data);
            datas[i]=0;
        }
        
    }
    for (int i = 0; i < 512; i++)
    {
        if(datas[i]!=NULL)
        {
            free_func(datas[i]);
        }
    }

    for (int i = 0; i < TEST_THREAD_NUM; i++)
    {
        pthread_create(&pids[i], NULL, thread_test, (void *)(rand() % 100));
    }
    for (int i = 0; i < TEST_THREAD_NUM; i++)
    {
        pthread_join(pids[i], NULL);
    }
}

int main()
{
    void *handle;

    char *error;
    handle = dlopen("./mymalloc.so", RTLD_LAZY);
    if (!handle)
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }
    dlerror();
    malloc_func = (my_malloc_ptr)dlsym(handle, "my_malloc");
    free_func = (my_free_ptr)dlsym(handle, "my_free");

    test();

    if ((error = dlerror()) != NULL)
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }

    dlclose(handle);
    return 0;
}