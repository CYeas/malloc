#include "library.h"

extern "C" void* my_malloc(size_t size)
{
    if((signed)size < 0)
    {
        return NULL;
    }
}

extern "C" void my_free(void* ptr)
{
    if(ptr == NULL)
    {
        return;
    }
}