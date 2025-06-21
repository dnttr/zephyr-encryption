//
// Created by Damian Netter on 20/05/2025.
//

#include "ZEKit/memory.hpp"

#include <cstring>
#include <new>
#include <sodium.h>

namespace ze_kit
{
    unsigned char *memory::allocate(const size_t size)
    {
        const auto mem = sodium_malloc(size);

        if (mem == nullptr)
        {
            throw std::bad_alloc();
        }

        return static_cast<unsigned char *>(mem);
    }

    void memory::deallocate(unsigned char *src, const size_t size)
    {
        if (src == nullptr)
        {
            return;
        }

        sodium_memzero(src, size);
        sodium_free(src);
    }

    unsigned char *memory::copy(unsigned char *src, const size_t size)
    {
        if (src == nullptr)
        {
            throw std::exception();
        }

        const auto mem = allocate(size);
        memcpy(mem, src, size);

        sodium_memzero(src, size);

        return mem;
    }

    bool memory::compare(const void *ptr1, const void *ptr2, const size_t size)
    {
        return sodium_memcmp(ptr1, ptr2, size) == 0;
    }
}
