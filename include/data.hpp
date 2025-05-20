//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

namespace ze_kit
{
    struct data
    {
    private:
        unsigned char *buffer;
        const size_t size;
    public:
        data(unsigned char *buffer, const size_t size): buffer(buffer), size(size) {}

        [[nodiscard]] unsigned char *get_buffer() const
        {
            return buffer;
        }

        [[nodiscard]] size_t get_size() const
        {
            return size;
        }
    };
}