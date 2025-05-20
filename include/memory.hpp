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
        static unsigned char *allocate(size_t size);

        static void deallocate(unsigned char *src , size_t size);

        [[nodiscard]] MALLOC
        static unsigned char *copy(unsigned char *src, size_t size); //int8_t?

        [[nodiscard]]
        static bool compare(const void* ptr1, const void* ptr2, size_t size);
    };
}