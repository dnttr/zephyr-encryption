//
// Created by Damian Netter on 22/05/2025.
//

#include "security.hpp"

#include <iostream>

#include "memory.hpp"
#include "setup.hpp"

void generate_str(const char *message, unsigned char **buffer, size_t *buffer_len)
{
    const size_t message_buffer_len = std::strlen(message);
    *buffer = ze_kit::memory::allocate(message_buffer_len);
    *buffer_len = message_buffer_len;

    std::memcpy(*buffer, message, message_buffer_len);
}

TEST_CASE("Asymmetric nonce generation")
{
    const auto nonce = ze_kit::security::build_nonce_asymmetric();
    REQUIRE(nonce.get() != nullptr);
}

TEST_CASE("Symmetric nonce generation")
{
    const auto nonce = ze_kit::security::build_nonce_symmetric();
    REQUIRE(nonce.get() != nullptr);
}

TEST_CASE("Asymmetric key generation")
{
    const auto [public_key, private_key] = ze_kit::security::build_key_asymmetric();
    REQUIRE(public_key.get() != nullptr);
    REQUIRE(private_key.get() != nullptr);
}

TEST_CASE("Symmetric key generation")
{
    const auto key = ze_kit::security::build_key_symmetric();
    REQUIRE(key.get() != nullptr);
}

TEST_CASE("Asymmetric encryption and decryption")
{
    unsigned char *message_buffer = nullptr;
    size_t message_buffer_len = 0;
    generate_str("Hello, World!", &message_buffer, &message_buffer_len);

    const auto [public_key, private_key] = ze_kit::security::build_key_asymmetric();
    const auto nonce = ze_kit::security::build_nonce_asymmetric();

    REQUIRE(public_key.get() != nullptr);
    REQUIRE(private_key.get() != nullptr);
    REQUIRE(nonce.get() != nullptr);

    const auto buffer = ze_kit::memory::copy(message_buffer, message_buffer_len); //there is no need for copying however just for the test purpose
    REQUIRE(buffer != nullptr);

    const auto data = ze_kit::guarded_ptr(new ze_kit::data(buffer, message_buffer_len));
    REQUIRE(data.get() != nullptr);

    const auto encrypted_data = ze_kit::security::encrypt_asymmetric(*public_key, *private_key, *data, *nonce);
    REQUIRE(encrypted_data.get() != nullptr);

    const auto decrypted_data = ze_kit::security::decrypt_asymmetric(*public_key, *private_key, *encrypted_data, *nonce);
    REQUIRE(decrypted_data.get() != nullptr);

    REQUIRE(ze_kit::memory::compare(data->get_buffer(), decrypted_data->get_buffer(), data->get_size()));

    ze_kit::memory::deallocate(message_buffer, message_buffer_len);
}
