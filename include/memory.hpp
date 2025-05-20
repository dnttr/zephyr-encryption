//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#if defined(__GNUC__) || defined(__clang__)
#define MALLOC __attribute__((malloc))
#else
#define MALLOC_ATTR
#endif

namespace ze_kit
{
    class memory
    {
    public:

        [[nodiscard]] MALLOC
        static void* allocate(size_t size);

        static void deallocate(void* ptr);

        [[nodiscard]] MALLOC
        static void* copy(const void* src, size_t size);

        static void zero(void* ptr, size_t size);

        [[nodiscard]]
        static int compare(const void* ptr1, const void* ptr2, size_t size);
    };
}