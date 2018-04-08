#include "malloc.h"

void* my_malloc(size_t size)
{
    if((signed)size < 0)
    {
        return NULL;
    }


    return NULL;
}

void my_free(void* ptr)
{
    if(ptr == NULL)
    {
        return;
    }


}