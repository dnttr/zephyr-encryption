//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include <iostream>
#include <jni.h>

#include <ZNBKit/jni/buffer.hpp>
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

        static guarded_ptr byteArray_to_data(JNIEnv *env, const jbyteArray& array)
        {
            if (array == nullptr)
            {
                throw std::invalid_argument("array is null");
            }

            const int arrayLength = env->GetArrayLength(array);
            std::vector<int8_t> buffer(arrayLength);
            znb_kit::buffer::get_ptr_byte(env, array, buffer.data(), arrayLength, 0);

            const auto data_buffer = memory::allocate(arrayLength);
            std::memcpy(data_buffer, buffer.data(), arrayLength);

            return guarded_ptr(new data(data_buffer, arrayLength));
        }

        static jbyteArray data_to_byteArray(JNIEnv *env, const data* data)
        {
            if (data == nullptr || data->get_buffer() == nullptr || data->get_size() == 0)
            {
                return nullptr;
            }

            const auto result = env->NewByteArray(data->get_size());
            if (result == nullptr)
            {
                return nullptr;
            }

            znb_kit::buffer::set_ptr_byte(env, result,
                                         reinterpret_cast<const int8_t*>(data->get_buffer()),
                                         data->get_size());

            return result;
        }
    };
}
