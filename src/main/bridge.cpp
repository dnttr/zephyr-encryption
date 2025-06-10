//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/bridge.hpp"

#include <sodium/randombytes.h>
#include <ZNBKit/debug.hpp>
#include <ZNBKit/jni/internal/wrapper.hpp>

#include "ZEKit/library.hpp"
#include "ZEKit/loader.hpp"
#include "ZEKit/security.hpp"
#include "ZEKit/util.hpp"

#define SESSION_AVAILABLE(UUID) if (!library::sessions.contains(UUID)) \
        { \
            debug_print_cerr("[ZE] Session does not exist. UUID: " + std::to_string(UUID)); \
            return nullptr; \
        } \

#define SESSION_AVAILABLE_NO_RET(UUID) if (!library::sessions.contains(UUID)) \
{ \
    debug_print_cerr("[ZE] Session does not exist. UUID: " + std::to_string(UUID)); \
    return; \
} \

#define SESSION_AVAILABLE_FAILURE_RET(UUID) if (!library::sessions.contains(UUID)) \
{ \
debug_print_cerr("[ZE] Session does not exist. UUID: " + std::to_string(UUID)); \
return FAILURE; \
} \

#define SYMMETRIC 0
#define ASYMMETRIC 1

/*
 * Refactor this piece of crap.
 */
namespace ze_kit
{
    void bridge::close_lib(JNIEnv *jni, [[maybe_unused]] jobject object)
    {
        znb_kit::wrapper::unregister_natives(jni, loader::name);
        znb_kit::wrapper::check_for_corruption();
    }

    jlong bridge::open_session([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject object)
    {
        uint64_t uuid;
        randombytes_buf(&uuid, sizeof(uuid));
        uuid &= 0x7FFFFFFFFFFFFFFF;

        while (library::sessions.contains(uuid))
        {
            randombytes_buf(&uuid, sizeof(uuid));
            uuid &= 0x7FFFFFFFFFFFFFFF;

            debug_print("[ZE] Collision detected, generating new UUID: " + std::to_string(uuid));
        }

        debug_print("[ZE] Opening session with UUID: " + std::to_string(uuid));

        library::sessions[uuid] = new session();

        return uuid;
    }

    jint bridge::close_session([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        SESSION_AVAILABLE_FAILURE_RET(uuid);
        debug_print("[ZE] Closing session with UUID: " + std::to_string(uuid));

        delete library::sessions[uuid];
        library::sessions.erase(uuid);

        return SUCCESS;
    }

    jbyteArray bridge::encrypt_symmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray data, const jbyteArray aead)
    {
        SESSION_AVAILABLE(uuid);
        debug_print("[ZE] Encrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (data == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, data);

        if (input_data == nullptr) {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session ->shared_key) {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;
        if (aead != nullptr) {
            aead_data = util::byteArray_to_data(jni, aead);

            debug_print("[ZE] AEAD data provided for session: " + std::to_string(uuid));
        } else {
            aead_data = guarded_ptr(new ze_kit::data(nullptr, 0));

            debug_print("[ZE] No AEAD data provided for session: " + std::to_string(uuid));
        }

        const ze_kit::data &key = *current_session->shared_key;
        const ze_kit::data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr encrypted = security::encrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (encrypted == nullptr) {
            return nullptr;

            debug_print_cerr("[ZE] Encryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
        }

        debug_print("[ZE] Encrypted data with UUID: " + std::to_string(uuid));

        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray bridge::decrypt_symmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray encrypted_data, const jbyteArray aead)
    {
        SESSION_AVAILABLE(uuid);

        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Decrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (encrypted_data == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr input_data = util::byteArray_to_data(jni, encrypted_data);

        if (input_data == nullptr) {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session ->shared_key) {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;

        if (aead != nullptr) {
            aead_data = util::byteArray_to_data(jni, aead);
        } else {
            aead_data = guarded_ptr(new data(nullptr, 0));
        }

        const data &key = *current_session->shared_key;
        const data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr decrypted = security::decrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (decrypted == nullptr) {
            debug_print_cerr("[ZE] Decryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }

    jbyteArray bridge::encrypt_asymmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray data)
    {
        SESSION_AVAILABLE(uuid);

        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Encrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (data == nullptr) {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr input_data = util::byteArray_to_data(jni, data);
        if (input_data == nullptr) {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->public_key || !current_session->secret_key) {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        const ze_kit::data &nonce = current_session->asymmetric_nonce
            ? *current_session->asymmetric_nonce
            : ze_kit::data(nullptr, 0);

        if (!current_session->asymmetric_nonce) {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr encrypted = security::encrypt_asymmetric(
            *current_session->public_key,
            *current_session->secret_key,
            *input_data,
            nonce);

        if (encrypted == nullptr) {
            return nullptr;
        }

        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray bridge::decrypt_asymmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray encrypted_data)
    {
        SESSION_AVAILABLE(uuid);

        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Decrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (encrypted_data == nullptr) {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr input_data = util::byteArray_to_data(jni, encrypted_data);
        if (input_data == nullptr) {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->public_key || !current_session->secret_key) {
            debug_print("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        const data &nonce = current_session->asymmetric_nonce
            ? *current_session->asymmetric_nonce
            : data(nullptr, 0);

        const guarded_ptr decrypted = security::decrypt_asymmetric(
            *current_session->public_key,
            *current_session->secret_key,
            *input_data,
            nonce);

        if (decrypted == nullptr) {
            debug_print_cerr("[ZE] Decryption (ASYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }

    void bridge::build_nonce([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        SESSION_AVAILABLE_NO_RET(uuid);

        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Building nonce for session: " + std::to_string(uuid));

        if (mode == SYMMETRIC) {
            if (guarded_ptr nonce = security::build_nonce_symmetric()) {
                current_session->symmetric_nonce = std::move(nonce);

                debug_print("[ZE] Successfully built symmetric nonce for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric nonce for session: " + std::to_string(uuid));
            }
        } else {
            if (guarded_ptr nonce = security::build_nonce_asymmetric()) {
                current_session->asymmetric_nonce = std::move(nonce);
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric nonce for session: " + std::to_string(uuid));
            }
        }
    }

    void bridge::build_key([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        SESSION_AVAILABLE_NO_RET(uuid);

        const auto current_session = library::sessions[uuid];

        if (mode == SYMMETRIC) {
            if (guarded_ptr key = security::build_key_symmetric()) {
                current_session->shared_key = std::move(key);

                debug_print("[ZE] Successfully built symmetric key for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric key for session: " + std::to_string(uuid));
            }
        } else {
            if (auto [pub_key, sec_key] = security::build_key_asymmetric(); pub_key != nullptr && sec_key != nullptr) {
                current_session->public_key = std::move(pub_key);
                current_session->secret_key = std::move(sec_key);

                debug_print("[ZE] Successfully built asymmetric keys for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric keys for session: " + std::to_string(uuid));
            }
        }
    }

    void bridge::set_symmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray key_buffer)
    {
        SESSION_AVAILABLE_NO_RET(uuid);

        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr) {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);

        if (!security::is_key_buffer_valid(0, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return;
        }

        debug_print("[ZE] Setting symmetric key for session: " + std::to_string(uuid));
        std::swap(current_session->shared_key, key);
    }

    void bridge::set_asymmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode, const jbyteArray key_buffer)
    {
        SESSION_AVAILABLE_NO_RET(uuid);
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr) {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);

        if (!security::is_key_buffer_valid(1, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return;
        }

        if (mode == 0)
        {
            debug_print("[ZE] Setting asymmetric public key for session: " + std::to_string(uuid));
            std::swap(current_session->public_key, key);
            return;
        }

        if (mode == 1)
        {
            debug_print("[ZE] Setting asymmetric secret key for session: " + std::to_string(uuid));
            std::swap(current_session->secret_key, key);
            return;
        }

        throw std::invalid_argument("Invalid mode");
    }

    void bridge::set_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode, const jbyteArray nonce_buffer)
    {
        SESSION_AVAILABLE_NO_RET(uuid);
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Setting nonce for session: " + std::to_string(uuid));

        if (nonce_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided nonce is null for session: " + std::to_string(uuid));
            return;
        }

        auto nonce = util::byteArray_to_data(jni, nonce_buffer);

        if (mode != 1 && mode != 0)
        {
            debug_print_cerr("[ZE] Invalid mode for nonce setting: " + std::to_string(mode));
            return;
        }

        if (!security::is_nonce_buffer_valid(mode, nonce->get_size()))
        {
            debug_print_cerr("[ZE] Provided nonce is invalid for session: " + std::to_string(uuid));
            return;
        }

        if (mode == 0)
        {
            debug_print("[ZE] Setting symmetric nonce for session: " + std::to_string(uuid));
            std::swap(current_session->symmetric_nonce, nonce);
        }
        else
        {
            debug_print("[ZE] Setting asymmetric nonce for session: " + std::to_string(uuid));
            std::swap(current_session->asymmetric_nonce, nonce);
        }

        throw std::runtime_error("Weird error, please report it to the developer");
    }

    jbyteArray bridge::get_symmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        SESSION_AVAILABLE(uuid);
        debug_print("[ZE] Getting symmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        if (!current_session->shared_key) {
            debug_print_cerr("[ZE] No symmetric key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->shared_key.get());
    }

    jbyteArray bridge::get_asymmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        SESSION_AVAILABLE(uuid);
        debug_print("[ZE] Getting asymmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        if (!(mode == 0 || mode == 1))
        {
            debug_print_cerr("[ZE] Invalid mode for asymmetric key retrieval: " + std::to_string(mode));
            return nullptr;
        }

        if (mode == 0) {
            if (!current_session->public_key) {
                debug_print_cerr("[ZE] No public key set for session: " + std::to_string(uuid));
                return nullptr;
            }
            return util::data_to_byteArray(jni, current_session->public_key.get());
        }

        if (!current_session->secret_key) {
            debug_print_cerr("[ZE] No secret key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->secret_key.get());
    }

    jbyteArray bridge::get_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        SESSION_AVAILABLE(uuid);
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Getting nonce for session: " + std::to_string(uuid));

        if (!(mode == 0 || mode == 1))
        {
            debug_print_cerr("[ZE] Invalid mode for nonce setting: " + std::to_string(mode));
            return nullptr;
        }

        if (mode == 0)
        {
            debug_print("[ZE] Getting symmetric nonce for session: " + std::to_string(uuid));

            if (!current_session->symmetric_nonce) {
                debug_print_cerr("[ZE] No symmetric nonce set for session: " + std::to_string(uuid));
                return nullptr;
            }

            return util::data_to_byteArray(jni, current_session->symmetric_nonce.get());
        }

        debug_print("[ZE] Getting asymmetric nonce for session: " + std::to_string(uuid));

        if (!current_session->asymmetric_nonce) {
            debug_print_cerr("[ZE] No asymmetric nonce set for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->asymmetric_nonce.get());
    }

    jbyteArray bridge::build_hash(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray message_buffer)
    {
        SESSION_AVAILABLE(uuid);
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Building hash for session: " + std::to_string(uuid));

        if (current_session->secret_key == nullptr)
        {
            debug_print_cerr("[ZE] No secret key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto secret_key = *current_session->secret_key;
        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);

        if (message_ptr == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert message buffer to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto hash = security::build_hash(secret_key, *message_ptr);

        return util::data_to_byteArray(jni, hash.get());
    }

    bool bridge::compare_hash(JNIEnv *jni, [[maybe_unused]] jobject object, const jlong uuid, const jbyteArray hash_buffer,
                              const jbyteArray message_buffer)
    {
        SESSION_AVAILABLE_FAILURE_RET(uuid);
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Comparing hash for session: " + std::to_string(uuid));

        if (current_session->secret_key == nullptr)
        {
            debug_print_cerr("[ZE] No secret key set for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (message_buffer == nullptr || hash_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message or hash is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const auto secret_key = *current_session->secret_key;
        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);
        const auto hash_ptr = util::byteArray_to_data(jni, hash_buffer);

        if (message_ptr == nullptr || hash_ptr == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert message or hash buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        return security::compare_hash(secret_key, *hash_ptr, *message_ptr);
    }

    void bridge::derive_secret_key(JNIEnv *jni, jobject object, const jlong uuid, jint mode, jbyteArray public_key_buffer)
    {
        SESSION_AVAILABLE_NO_RET(uuid);
        const auto current_session = library::sessions[uuid];
    }

    void bridge::build_derivable_key(JNIEnv *jni, jobject object, const jlong uuid)
    {
        SESSION_AVAILABLE_NO_RET(uuid);
        const auto current_session = library::sessions[uuid];
    }

    void bridge::derive_hash_key(JNIEnv *jni, jobject object, const jlong uuid)
    {
        SESSION_AVAILABLE_NO_RET(uuid);
        const auto current_session = library::sessions[uuid];
    }
}
