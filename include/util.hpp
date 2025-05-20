//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include "data.hpp"

namespace ze_kit
{
    class util
    {
    public:
        static bool is_data_valid(const data &key, const data &buffer, const data &nonce)
        {
            if (key.get_buffer() == nullptr || key.get_size() == 0)
            {
                return false;
            }

            if (buffer.get_buffer() == nullptr || buffer.get_size() == 0)
            {
                return false;
            }

            if (nonce.get_buffer() == nullptr || nonce.get_size() == 0)
            {
                return false;
            }

            return true;
        }
    };
}
