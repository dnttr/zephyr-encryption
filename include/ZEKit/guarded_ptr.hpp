//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include <memory>

#include "data.hpp"
#include "memory.hpp"

namespace ze_kit
{
    class guarded_ptr : public std::unique_ptr<data, void (*)(data *)>
    {
        using _deleter = void (*)(data *);

        static void deleter(data *data)
        {
            if (!data)
            {
                return;
            }

            memory::deallocate(data->get_buffer(), data->get_size());
            delete data;
        }
    public:
        explicit guarded_ptr(data *ptr) : std::unique_ptr<data, _deleter>(ptr, deleter)
        {
        }

        guarded_ptr() : guarded_ptr(nullptr)
        {
        }

        explicit guarded_ptr(std::nullptr_t) : std::unique_ptr<data, _deleter>(nullptr, deleter)
        {
        }
    };
}
