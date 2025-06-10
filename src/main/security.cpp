//
// Created by Damian Netter on 20/05/2025.
//

#define PUBLIC_KEY crypto_box_PUBLICKEYBYTES
#define PRIVATE_KEY crypto_box_SECRETKEYBYTES

#define SYMMETRIC_KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#define HASH crypto_generichash_blake2b_BYTES
#define CTX crypto_kdf_blake2b_CONTEXTBYTES
#define SESSION crypto_kx_SESSIONKEYBYTES

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

#include "ZEKit/security.hpp"

#include <sodium.h>
#include <stdexcept>

#include "ZEKit/library.hpp"
#include "ZEKit/util.hpp"

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
        if (!util::is_data_valid(public_key, private_key, buffer, nonce))
        {
            throw std::invalid_argument("Invalid arguments were provided ");
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

    bool security::is_key_buffer_valid(const int mode, const size_t size)
    {
        if (mode == 0)
        {
            return size == SYMMETRIC_KEY;
        }

        return size == PRIVATE_KEY;
    }

    bool security::is_nonce_buffer_valid(const int mode, const size_t size)
    {
        if (mode == 0)
        {
            return size == SYMMETRIC_NONCE;
        }

        return size == ASYMMETRIC_NONCE;
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

    std::pair<guarded_ptr, guarded_ptr> security::build_derivable_key() //does such word even exist?
    {

        const auto public_key = memory::allocate(PUBLIC_KEY);
        const auto private_key = memory::allocate(PRIVATE_KEY);

        if (crypto_kx_keypair(public_key, private_key) != 0)
        {
            throw std::runtime_error("Failed to generate key pair (derivable)");
        }

        guarded_ptr public_key_ptr(new data(public_key, PUBLIC_KEY));
        guarded_ptr private_key_ptr(new data(private_key, PRIVATE_KEY));

        return std::make_pair(public_key_ptr, private_key_ptr);
    }

    guarded_ptr security::build_hash(const data &key, const data &buffer)
    {
        if (!util::is_data_valid(key, buffer))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const auto hash = memory::allocate(HASH);

        if (crypto_generichash_blake2b(hash, HASH, buffer.get_buffer(), buffer.get_size(), key.get_buffer(), key.get_size()) != 0)
        {
            memory::deallocate(hash, HASH);

            throw std::runtime_error("Failed to generate hash");
        }

        return guarded_ptr(new data(hash, HASH));
    }

    bool security::compare_hash(const data &key, const data &received, const data &buffer)
    {
        if (!util::is_data_valid(key, received, buffer))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const guarded_ptr computed = build_hash(key, buffer);

        return memory::compare(received.get_buffer(), computed->get_buffer(), HASH);
    }

    guarded_ptr security::derive_key(const data &receive)
    {
        if (!util::is_data_valid(receive))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const auto subkey = memory::allocate(SESSION);

        constexpr char ctx[CTX] = { 'Z', 'E', 'K', 'i', 't', 'C', 'T', 'X'};
        constexpr uint64_t subkey_id = 0;

        if (crypto_kdf_blake2b_derive_from_key(subkey, SESSION, subkey_id, ctx, receive.get_buffer()) != 0)
        {
            memory::deallocate(subkey, SESSION);

            throw std::runtime_error("Failed to derive key");
        }

        return guarded_ptr(new data(subkey, SESSION));
    }

    std::pair<guarded_ptr, guarded_ptr> security::derive_client_key(const data &server_public_key, const data &client_public_key, const data &client_private_key)
    {
        if (!util::is_data_valid(client_public_key, server_public_key, client_private_key))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const auto receive = memory::allocate(SESSION);
        const auto transmission = memory::allocate(SESSION);

        if (crypto_kx_client_session_keys(receive, transmission, client_public_key.get_buffer(), client_private_key.get_buffer(), server_public_key.get_buffer()) != 0)
        {
            memory::deallocate(receive, SESSION);
            memory::deallocate(transmission, SESSION);

            throw std::runtime_error("Failed to derive client key");
        }

        guarded_ptr receive_ptr(new data(receive, SESSION));
        guarded_ptr transmission_ptr(new data(transmission, SESSION));

        return std::make_pair(receive_ptr, transmission_ptr);
    }

    std::pair<guarded_ptr, guarded_ptr> security::derive_server_key(const data &client_public_key, const data &server_public_key, const data &server_private_key)
    {
        if (!util::is_data_valid(client_public_key, server_public_key, server_private_key))
        {
            throw std::invalid_argument("Invalid arguments were provided");
        }

        const auto receive = memory::allocate(SESSION);
        const auto transmission = memory::allocate(SESSION);

        if (crypto_kx_server_session_keys(receive, transmission, server_public_key.get_buffer(), server_private_key.get_buffer(), client_public_key.get_buffer()) != 0)
        {
            memory::deallocate(receive, SESSION);
            memory::deallocate(transmission, SESSION);

            throw std::runtime_error("Failed to derive server key");
        }

        guarded_ptr receive_ptr(new data(receive, SESSION));
        guarded_ptr transmission_ptr(new data(transmission, SESSION));

        return std::make_pair(receive_ptr, transmission_ptr);
    }

    std::pair<guarded_ptr, guarded_ptr> security::build_key_asymmetric()
    {
        const auto public_key = memory::allocate(PUBLIC_KEY);
        const auto private_key = memory::allocate(PRIVATE_KEY);

        if (crypto_box_curve25519xchacha20poly1305_keypair(public_key, private_key) != 0)
        {
            memory::deallocate(public_key, PUBLIC_KEY);
            memory::deallocate(private_key, PRIVATE_KEY);

            throw std::runtime_error("Failed to generate asymmetric key");
        }

        guarded_ptr public_key_ptr(new data(public_key, PUBLIC_KEY));
        guarded_ptr private_key_ptr(new data(private_key, PRIVATE_KEY));

        return std::make_pair(std::move(public_key_ptr), std::move(private_key_ptr));
    }
}
