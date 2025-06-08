//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include "guarded_ptr.hpp"

namespace ze_kit
{
    class security
    {
        static guarded_ptr build_nonce(size_t size);

    public:
        static guarded_ptr encrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce);
        static guarded_ptr decrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce);

        static guarded_ptr encrypt_asymmetric(const data &public_key, const data &private_key, const data &buffer, const data &nonce);
        static guarded_ptr decrypt_asymmetric(const data &public_key, const data &private_key, const data &buffer, const data &nonce);

        static guarded_ptr build_nonce_symmetric();
        static guarded_ptr build_nonce_asymmetric();

        static guarded_ptr build_key_symmetric();

        static std::pair<guarded_ptr, guarded_ptr> build_key_asymmetric();

        static bool is_key_buffer_valid(int mode, size_t size);
        static bool is_nonce_buffer_valid(int mode, size_t size);
    };
}
