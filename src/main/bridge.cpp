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
            debug_print("[ZE] Session does not exist. UUID: " + std::to_string(UUID)); \
            return nullptr; \
        } \

#define SESSION_AVAILABLE_NO_RET(UUID) if (!library::sessions.contains(UUID)) \
{ \
    debug_print("[ZE] Session does not exist. UUID: " + std::to_string(UUID)); \
} \

namespace ze_kit
{
    void bridge::close_lib(JNIEnv *jni, jobject object)
    {
        znb_kit::wrapper::unregister_natives(jni, loader::name);
        znb_kit::wrapper::check_for_corruption();
    }

    jlong bridge::open_session(JNIEnv *env, jobject object)
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

    jint bridge::close_session(JNIEnv *env, jobject object, const jlong uuid)
    {
        if (!library::sessions.contains(uuid))
        {
            debug_print("[ZE] Session does not exist. UUID: " + std::to_string(uuid));
            return FAILURE;
        }

        debug_print("[ZE] Closing session with UUID: " + std::to_string(uuid));

        delete library::sessions[uuid];
        library::sessions.erase(uuid);

        return SUCCESS;;
    }

    jbyteArray bridge::encrypt_symmetric(JNIEnv *env, jobject object, jlong uuid, jbyteArray data, jbyteArray aead)
    {
        SESSION_AVAILABLE(uuid);

        session* current_session = library::sessions[uuid];

        guarded_ptr input_data = util::byteArray_to_data(env, data);
        if (input_data == nullptr) {
            return nullptr;
        }

        guarded_ptr aead_data;
        if (aead != nullptr) {
            aead_data = util::byteArray_to_data(env, aead);
        } else {
            aead_data = guarded_ptr(new ze_kit::data(nullptr, 0));
        }

        const ze_kit::data& key = *current_session->shared_key;
        const ze_kit::data& nonce = current_session->get_symmetric_nonce();

        guarded_ptr encrypted = security::encrypt_symmetric(key, *aead_data, *input_data, nonce);
        if (encrypted == nullptr) {
            return nullptr;
        }

        return util::data_to_byteArray(env, encrypted.get());
    }

    jbyteArray bridge::decrypt_symmetric(JNIEnv *env, jobject object, jlong uuid, jbyteArray encrypted_data,
        jbyteArray aead)
    {
        SESSION_AVAILABLE(uuid);

        session* current_session = library::sessions[uuid];

        guarded_ptr input_data = util::byteArray_to_data(env, encrypted_data);
        if (input_data == nullptr) {
            return nullptr;
        }

        guarded_ptr aead_data;
        if (aead != nullptr) {
            aead_data = util::byteArray_to_data(env, aead);
        } else {
            aead_data = guarded_ptr(new data(nullptr, 0));
        }

        const data& key = *current_session->shared_key;
        const data& nonce = current_session->get_symmetric_nonce();

        guarded_ptr decrypted = security::decrypt_symmetric(key, *aead_data, *input_data, nonce);
        if (decrypted == nullptr) {
            return nullptr;
        }

        return util::data_to_byteArray(env, decrypted.get());
    }

    jbyteArray bridge::encrypt_asymmetric(JNIEnv *env, jobject object, jlong uuid, jbyteArray data)
    {
        SESSION_AVAILABLE(uuid);

        session* current_session = library::sessions[uuid];

        guarded_ptr input_data = util::byteArray_to_data(env, data);
        if (input_data == nullptr) {
            return nullptr;
        }

        if (!current_session->public_key || !current_session->secret_key) {
            debug_print("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        const ze_kit::data& nonce = current_session->asymmetric_nonce
            ? *current_session->asymmetric_nonce
            : ze_kit::data(nullptr, 0);

        guarded_ptr encrypted = security::encrypt_asymmetric(
            *current_session->public_key,
            *current_session->secret_key,
            *input_data,
            nonce);

        if (encrypted == nullptr) {
            return nullptr;
        }

        return util::data_to_byteArray(env, encrypted.get());
    }

    jbyteArray bridge::decrypt_asymmetric(JNIEnv *env, jobject object, jlong uuid, jbyteArray encrypted_data)
    {
        SESSION_AVAILABLE(uuid);

        session* current_session = library::sessions[uuid];

        guarded_ptr input_data = util::byteArray_to_data(env, encrypted_data);
        if (input_data == nullptr) {
            return nullptr;
        }

        if (!current_session->public_key || !current_session->secret_key) {
            debug_print("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        const ze_kit::data& nonce = current_session->asymmetric_nonce
            ? *current_session->asymmetric_nonce
            : ze_kit::data(nullptr, 0);

        guarded_ptr decrypted = security::decrypt_asymmetric(
            *current_session->public_key,
            *current_session->secret_key,
            *input_data,
            nonce);

        if (decrypted == nullptr) {
            return nullptr;
        }

        return util::data_to_byteArray(env, decrypted.get());
    }

    void bridge::build_nonce(JNIEnv *env, jobject object, jlong uuid, jint mode)
    {
        SESSION_AVAILABLE_NO_RET(uuid);

        session* current_session = library::sessions[uuid];

        if (mode == 0) {
            if (guarded_ptr nonce = security::build_nonce_symmetric()) {
                current_session->symmetric_nonce = std::move(nonce);
            }
            else
            {
                debug_print_cerr("Failed to build symmetric nonce for session: " + std::to_string(uuid));
            }
        } else {
            if (guarded_ptr nonce = security::build_nonce_asymmetric()) {
                current_session->asymmetric_nonce = std::move(nonce);
            }
            else
            {
                debug_print_cerr("Failed to build asymmetric nonce for session: " + std::to_string(uuid));
            }
        }
    }

    void bridge::build_key(JNIEnv *env, [[maybe_unused]] jobject object, const jlong uuid, const jint key_type)
    {
        SESSION_AVAILABLE_NO_RET(uuid);

        session* current_session = library::sessions[uuid];

        if (key_type == 0) {
            if (guarded_ptr key = security::build_key_symmetric()) {
                current_session->shared_key = std::move(key);

                debug_print("Successfully built symmetric key for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("Failed to build symmetric key for session: " + std::to_string(uuid));
            }
        } else {
            if (auto [pub_key, sec_key] = security::build_key_asymmetric(); pub_key != nullptr && sec_key != nullptr) {
                current_session->public_key = std::move(pub_key);
                current_session->secret_key = std::move(sec_key);

                debug_print("Successfully built asymmetric keys for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("Failed to build asymmetric keys for session: " + std::to_string(uuid));
            }
        }
    }
}
