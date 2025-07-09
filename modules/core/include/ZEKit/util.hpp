//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include <iostream>
#include <jni.h>
#include <vector>
#include <ZNBKit/jni/buffer.hpp>

#include "ZEKit/data.hpp"

namespace ze_kit
{
    class util
    {
    public:
        static bool is_ptr_valid(const guarded_ptr &ptr)
        {
            return ptr != nullptr;
        }
        static bool is_data_valid(const data &b1)
        {
            return !(b1.get_buffer() == nullptr || b1.get_size() == 0);
        }

        static bool is_data_valid(const data &b1, const data &b2)
        {
            if (b1.get_buffer() == nullptr || b1.get_size() == 0)
            {
                return false;
            }

            if (b2.get_buffer() == nullptr || b2.get_size() == 0)
            {
                return false;
            }

            return true;
        }

        static bool is_data_valid(const data &b1, const data &b2, const data &b3)
        {
            if (b1.get_buffer() == nullptr || b1.get_size() == 0)
            {
                return false;
            }

            if (b2.get_buffer() == nullptr || b2.get_size() == 0)
            {
                return false;
            }

            if (b3.get_buffer() == nullptr || b3.get_size() == 0)
            {
                return false;
            }

            return true;
        }

        static bool is_data_valid(const data &b1, const data &b2, const data &b3, const data &b4)
        {
            if (b1.get_buffer() == nullptr || b1.get_size() == 0)
            {
                return false;
            }

            if (b2.get_buffer() == nullptr || b2.get_size() == 0)
            {
                return false;
            }

            if (b3.get_buffer() == nullptr || b3.get_size() == 0)
            {
                return false;
            }

            if (b4.get_buffer() == nullptr || b4.get_size() == 0)
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

    inline guarded_ptr encrypt_asymmetric_message(const session *current_session, const guarded_ptr &message_data)
    {
        if (!current_session || !message_data)
        {
            return guarded_ptr(nullptr);
        }

        if (!current_session->asymmetric_nonce ||
            !current_session->received_public_key_2 ||
            !current_session->built_private_key)
        {
            return guarded_ptr(nullptr);
        }

        const data &nonce = *current_session->asymmetric_nonce;

        return security::encrypt_asymmetric(
            *current_session->received_public_key_2,
            *current_session->built_private_key,
            *message_data,
            nonce);
    }

    inline guarded_ptr decrypt_asymmetric_message(const session *current_session, const guarded_ptr &message_data)
    {
        if (!current_session || !message_data)
        {
            return guarded_ptr(nullptr);
        }

        if (!current_session->asymmetric_nonce ||
            !current_session->received_public_key_2 ||
            !current_session->built_private_key)
        {
            return guarded_ptr(nullptr);
        }

        const data &nonce = *current_session->asymmetric_nonce;

        return security::decrypt_asymmetric(
            *current_session->received_public_key_2,
            *current_session->built_private_key,
            *message_data,
            nonce);
    }
}
