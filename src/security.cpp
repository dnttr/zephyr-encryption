//
// Created by Damian Netter on 20/05/2025.
//

#define PUBLIC_KEY crypto_box_PUBLICKEYBYTES
#define PRIVATE_KEY crypto_box_SECRETKEYBYTES

#define SYMMETRIC_KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES

// I think they're equal, though for the sake of clarity let's keep them separate
#define SYMMETRIC_NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define ASYMMETRIC_NONCE crypto_box_curve25519xchacha20poly1305_NONCEBYTES

#define AEAD crypto_aead_xchacha20poly1305_ietf_ABYTES
#define MAC crypto_box_curve25519xchacha20poly1305_MACBYTES

// It takes too long to realize which one is the symmetric one and which one is the asymmetric one, so just for my sanity, ill define them here
#define ENCRYPT_SYMMETRIC crypto_aead_xchacha20poly1305_ietf_encrypt
#define ENCRYPT_ASYMMETRIC crypto_box_curve25519xchacha20poly1305_easy

#define DECRYPT_SYMMETRIC crypto_aead_xchacha20poly1305_ietf_decrypt
#define DECRYPT_ASYMMETRIC crypto_box_curve25519xchacha20poly1305_open_easy

#include "security.hpp"

#include <sodium.h>
#include <stdexcept>

#include "library.hpp"
#include "util.hpp"

namespace ze_kit
{
    guarded_ptr security::encrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce)
    {
        if (!util::is_data_valid(key, buffer, nonce))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const size_t initial_msg_size = buffer.get_size() + AEAD;
        const auto msg_buffer = memory::allocate(initial_msg_size);

        if (msg_buffer == nullptr)
        {
            throw std::bad_alloc();
        }

        unsigned long long msg_size;
        if (ENCRYPT_SYMMETRIC(msg_buffer, &msg_size, buffer.get_buffer(), buffer.get_size(), aead.get_buffer(), aead.get_size(), nullptr, nonce.get_buffer(), key.get_buffer()) != SUCCESS)
        {
            memory::deallocate(msg_buffer, initial_msg_size);
            throw std::exception();
        }

        return guarded_ptr(new data(msg_buffer, msg_size));
    }

    guarded_ptr security::decrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce)
    {
        if (!util::is_data_valid(key, buffer, nonce))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const size_t initial_msg_size = buffer.get_size();

        if (initial_msg_size < AEAD)
        {
            return guarded_ptr(nullptr);
        }

        const auto msg_buffer = memory::allocate(initial_msg_size);

        if (msg_buffer == nullptr)
        {
            throw std::bad_alloc();
        }

        unsigned long long msg_size;

        if (DECRYPT_SYMMETRIC(msg_buffer, &msg_size, nullptr, buffer.get_buffer(), buffer.get_size(), aead.get_buffer(), aead.get_size(), nonce.get_buffer(), key.get_buffer()) != SUCCESS)
        {
            memory::deallocate(msg_buffer, initial_msg_size);

            return guarded_ptr(nullptr);
        }

        return guarded_ptr(new data(msg_buffer, msg_size));
    }

    guarded_ptr security::encrypt_asymmetric(const data &public_key, const data &private_key, const data &buffer, const data &nonce)
    {
        if (util::is_data_valid(public_key, private_key, buffer, nonce))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const size_t msg_size = buffer.get_size() + MAC;
        const auto msg_buffer = memory::allocate(msg_size);

        if (msg_buffer == nullptr)
        {
            throw std::bad_alloc();
        }

        if (ENCRYPT_ASYMMETRIC(msg_buffer, buffer.get_buffer(), buffer.get_size(), nonce.get_buffer(), public_key.get_buffer(), private_key.get_buffer()) != SUCCESS)
        {
            memory::deallocate(msg_buffer, msg_size);
            throw std::exception();
        }

        return guarded_ptr(new data(msg_buffer, msg_size));
    }

    guarded_ptr security::decrypt_asymmetric(const data &public_key, const data &private_key, const data &buffer, const data &nonce)
    {
        if (!util::is_data_valid(public_key, private_key, buffer, nonce))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const size_t initial_msg_size = buffer.get_size();

        if (initial_msg_size < MAC)
        {
            return guarded_ptr(nullptr);
        }

        const auto msg_size = initial_msg_size - MAC;
        const auto msg_buffer = memory::allocate(msg_size);

        if (msg_buffer == nullptr)
        {
            throw std::bad_alloc();
        }

        if (DECRYPT_ASYMMETRIC(msg_buffer, buffer.get_buffer(), buffer.get_size(), nonce.get_buffer(), public_key.get_buffer(), private_key.get_buffer()) != SUCCESS)
        {
            memory::deallocate(msg_buffer, msg_size);
            return guarded_ptr(nullptr);
        }

        return guarded_ptr(new data(msg_buffer, msg_size));
    }

    guarded_ptr security::build_nonce(const size_t size)
    {
        const auto buffer = memory::allocate(size);
        randombytes(buffer, size);

        return guarded_ptr(new data(buffer, size));
    }

    guarded_ptr security::build_nonce_symmetric()
    {
        return build_nonce(SYMMETRIC_NONCE);
    }

    guarded_ptr security::build_nonce_asymmetric()
    {
        return build_nonce(ASYMMETRIC_NONCE);
    }

    guarded_ptr security::build_key_symmetric()
    {
        const auto key = memory::allocate(SYMMETRIC_KEY);

        crypto_aead_xchacha20poly1305_ietf_keygen(key);

        return guarded_ptr(new data(key, SYMMETRIC_KEY));
    }

    std::pair<guarded_ptr, guarded_ptr> security::build_key_asymmetric()
    {
        const auto public_key = memory::allocate(PUBLIC_KEY);
        const auto private_key = memory::allocate(PRIVATE_KEY);

        crypto_box_curve25519xchacha20poly1305_keypair(public_key, private_key);

        guarded_ptr public_key_ptr(new data(public_key, PUBLIC_KEY));
        guarded_ptr private_key_ptr(new data(private_key, PRIVATE_KEY));

        return std::make_pair(public_key_ptr, private_key_ptr);
    }
}
