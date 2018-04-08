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

typedef void*(*my_malloc_ptr)(size_t);
typedef void (*my_free_ptr)(void*);


void test(my_malloc_ptr malloc_func,my_free_ptr free_func)
{
    char* data = (char*)malloc_func(100);
    if(data==NULL)
    {
        return;
    }
    strcpy(data,"test_str");
    printf("%s\n",data);
    free_func(data);

    data = (char*)malloc_func(getpagesize()*3);
    free_func(data);

    unsigned int seed = (unsigned int)time(NULL);
    //unsigned int seed = 1523191652;
    printf("seed : %d\n",seed);
    
    srand(seed);
    for(int i=0;i<100;i++)
    {
        printf("%d\n",i);
        data = (char*)malloc_func(rand()%getpagesize()*2);
        free_func(data);
    }

}


int main()
{
    void *handle;

    char *error;
    handle = dlopen ("./mymalloc.so", RTLD_LAZY);
    if (!handle)
    {
        fprintf (stderr, "%s\n", dlerror());
        exit(1);
    }
    dlerror();
    my_malloc_ptr malloc_func = (my_malloc_ptr)dlsym(handle, "my_malloc");
    my_free_ptr free_func = (my_free_ptr)dlsym(handle,"my_free");

    test(malloc_func,free_func);

    if ((error = dlerror()) != NULL)
    {
        fprintf (stderr, "%s\n", error);
        exit(1);
    }

    dlclose(handle);
    return 0;
}