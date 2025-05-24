//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include <iostream>

#include "data.hpp"

namespace ze_kit
{
    class util
    {
    public:
        static bool is_data_valid(const data &public_key, const data &private_key, const data &buffer, const data &nonce)
        {
            if (public_key.get_buffer() == nullptr || public_key.get_size() == 0)
            {
                std::cout << "xd1" << std::endl;
                return false;
            }

            if (private_key.get_buffer() == nullptr || private_key.get_size() == 0)
            {

                std::cout << "xd2" << std::endl;
                return false;
            }

            if (buffer.get_buffer() == nullptr || buffer.get_size() == 0)
            {
                std::cout << "xd3" << std::endl;
                return false;
            }

            if (nonce.get_buffer() == nullptr || nonce.get_size() == 0)
            {
                std::cout << "xd4" << std::endl;
                return false;
            }

            return true;
        }

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
