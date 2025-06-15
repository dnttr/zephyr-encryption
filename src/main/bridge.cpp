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

namespace ze_kit
{
    enum class EncryptionMode
    {
        SYMMETRIC = 0,
        ASYMMETRIC = 1
    };

    enum class KeyType
    {
        PUBLIC = 0,
        PRIVATE = 1
    };

    enum class SideType
    {
        SERVER = 0,
        CLIENT = 1
    };

    bool validate_session(const uint64_t uuid, const bool log_error = true)
    {
        if (!library::sessions.contains(uuid))
        {
            if (log_error)
            {
                debug_print_cerr("[ZE] Session does not exist. UUID: " + std::to_string(uuid));
            }
            return false;
        }
        return true;
    }
}

//class is too large, need to split it up along with new naming conventions, they got a bit messy
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
        if (!validate_session(uuid))
        {
            return FAILURE;
        }

        debug_print("[ZE] Closing session with UUID: " + std::to_string(uuid));

        delete library::sessions[uuid];
        library::sessions.erase(uuid);

        return SUCCESS;
    }

    jbyteArray bridge::encrypt_symmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                         const jbyteArray message_buffer, const jbyteArray aead_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }

        debug_print("[ZE] Encrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;

        if (aead_buffer != nullptr)
        {
            aead_data = util::byteArray_to_data(jni, aead_buffer);
            debug_print("[ZE] AEAD data provided for session: " + std::to_string(uuid));
        }
        else
        {
            aead_data = guarded_ptr(new data(nullptr, 0));
            debug_print("[ZE] No AEAD data provided for session: " + std::to_string(uuid));
        }

        const data &key = *current_session->shared_key_1;
        const data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr encrypted = security::encrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (encrypted == nullptr)
        {
            debug_print_cerr("[ZE] Encryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        debug_print("[ZE] Encrypted data with UUID: " + std::to_string(uuid));
        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray bridge::decrypt_symmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                         const jbyteArray message_buffer, const jbyteArray aead_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Decrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;
        if (aead_buffer != nullptr)
        {
            aead_data = util::byteArray_to_data(jni, aead_buffer);
        }
        else
        {
            aead_data = guarded_ptr(new data(nullptr, 0));
        }

        const data &key = *current_session->shared_key_1;
        const data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr decrypted = security::decrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (decrypted == nullptr)
        {
            debug_print_cerr("[ZE] Decryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }

    guarded_ptr encrypt_asymmetric_message(const session *current_session, const guarded_ptr &message_data)
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

    guarded_ptr decrypt_asymmetric_message(const session *current_session, const guarded_ptr &message_data)
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

    jbyteArray bridge::encrypt_asymmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                          const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Encrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr encrypted = encrypt_asymmetric_message(current_session, input_data);

        if (!encrypted)
        {
            debug_print_cerr("[ZE] Encryption (ASYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray bridge::decrypt_asymmetric(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                          const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Decrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr decrypted = decrypt_asymmetric_message(current_session, input_data);

        if (decrypted == nullptr)
        {
            debug_print_cerr("[ZE] Decryption (ASYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }

    jbyteArray bridge::get_exchange_message(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (current_session->shared_key_1 == nullptr)
        {
            debug_print_cerr("[ZE] No symmetric key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto key = encrypt_asymmetric_message(current_session, current_session->shared_key_1);
        if (!key)
        {
            debug_print_cerr("[ZE] Failed to encrypt symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        const jbyteArray result = util::data_to_byteArray(jni, key.get());

        debug_print("[ZE] Exchange message prepared for session: " + std::to_string(uuid));

        return result;
    }

    void bridge::set_exchange_message(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                      const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting exchange message for session: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided exchange message is null for session: " + std::to_string(uuid));
            return;
        }

        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);
        if (input_data == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert exchange message to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return;
        }

        guarded_ptr decrypted_key = decrypt_asymmetric_message(current_session, input_data);
        if (!decrypted_key)
        {
            debug_print_cerr("[ZE] Failed to decrypt exchange message for session: " + std::to_string(uuid));
            return;
        }

        current_session->shared_key_1 = std::move(decrypted_key);

        debug_print("[ZE] Successfully set exchange message for session: " + std::to_string(uuid));
    }

    void bridge::build_nonce([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building nonce for session: " + std::to_string(uuid));

        if (mode == static_cast<jint>(EncryptionMode::SYMMETRIC))
        {
            guarded_ptr nonce = security::build_nonce_symmetric();
            if (nonce)
            {
                current_session->symmetric_nonce = std::move(nonce);
                debug_print("[ZE] Successfully built symmetric nonce for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric nonce for session: " + std::to_string(uuid));
            }
        }
        else if (mode == static_cast<jint>(EncryptionMode::ASYMMETRIC))
        {
            guarded_ptr nonce = security::build_nonce_asymmetric();
            if (nonce)
            {
                current_session->asymmetric_nonce = std::move(nonce);
                debug_print("[ZE] Successfully built asymmetric nonce for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric nonce for session: " + std::to_string(uuid));
            }
        }
        else
        {
            debug_print_cerr("[ZE] Invalid mode for nonce building: " + std::to_string(mode));
        }
    }

    void bridge::build_key([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building key for session: " + std::to_string(uuid));

        if (mode == static_cast<jint>(EncryptionMode::SYMMETRIC))
        {
            if (guarded_ptr key = security::build_key_symmetric())
            {
                current_session->shared_key_1 = std::move(key);
                debug_print("[ZE] Successfully built symmetric key for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric key for session: " + std::to_string(uuid));
            }
        }
        else if (mode == static_cast<jint>(EncryptionMode::ASYMMETRIC))
        {
            if (auto [pub_key, sec_key] = security::build_key_asymmetric(); pub_key && sec_key)
            {
                current_session->built_public_key = std::move(pub_key);
                current_session->built_private_key = std::move(sec_key);
                debug_print("[ZE] Successfully built asymmetric keys for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric keys for session: " + std::to_string(uuid));
            }
        }
        else
        {
            debug_print_cerr("[ZE] Invalid mode for key building: " + std::to_string(mode));
        }
    }

    void bridge::set_symmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        if (!security::is_key_buffer_valid(0, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return;
        }

        debug_print("[ZE] Setting symmetric key for session: " + std::to_string(uuid));
        std::swap(current_session->shared_key_1, key);
    }

    void bridge::set_asymmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode,
                                    const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        if (!security::is_key_buffer_valid(1, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return;
        }

        switch (mode)
        {
        case static_cast<jint>(KeyType::PUBLIC):
            {
                debug_print("[ZE] Setting asymmetric public key for session: " + std::to_string(uuid));
                std::swap(current_session->built_public_key, key);
                break;
            }
        case static_cast<jint>(KeyType::PRIVATE):
            {
                debug_print("[ZE] Setting asymmetric private key for session: " + std::to_string(uuid));
                std::swap(current_session->built_private_key, key);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for asymmetric key setting: " + std::to_string(mode));
                break;
            }
        }
    }

    void bridge::set_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode,
                           const jbyteArray nonce_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting nonce for session: " + std::to_string(uuid));

        if (nonce_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided nonce is null for session: " + std::to_string(uuid));
            return;
        }

        auto nonce = util::byteArray_to_data(jni, nonce_buffer);
        if (nonce == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert nonce buffer to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        if (!security::is_nonce_buffer_valid(mode, nonce->get_size()))
        {
            debug_print_cerr("[ZE] Provided nonce is invalid for session: " + std::to_string(uuid));
            return;
        }

        switch (mode)
        {
        case static_cast<jint>(EncryptionMode::SYMMETRIC):
            {
                debug_print("[ZE] Setting symmetric nonce for session: " + std::to_string(uuid));
                std::swap(current_session->symmetric_nonce, nonce);
                break;
            }
        case static_cast<jint>(EncryptionMode::ASYMMETRIC):
            {
                debug_print("[ZE] Setting asymmetric nonce for session: " + std::to_string(uuid));
                std::swap(current_session->asymmetric_nonce, nonce);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for nonce setting: " + std::to_string(mode));
                break;
            }
        }
    }

    void bridge::set_asymmetric_received_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                             jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        std::swap(current_session->received_public_key_2, key);
    }

    jbyteArray bridge::get_symmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Getting symmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] No symmetric key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->shared_key_1.get());
    }

    jbyteArray bridge::get_asymmetric_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Getting asymmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        switch (mode)
        {
        case static_cast<jint>(KeyType::PUBLIC):
            {
                if (!current_session->built_public_key)
                {
                    debug_print_cerr("[ZE] No public key set for session: " + std::to_string(uuid));
                    return nullptr;
                }
                return util::data_to_byteArray(jni, current_session->built_public_key.get());
            }
        case static_cast<jint>(KeyType::PRIVATE):
            {
                if (!current_session->built_private_key)
                {
                    debug_print_cerr("[ZE] No private key set for session: " + std::to_string(uuid));
                    return nullptr;
                }
                return util::data_to_byteArray(jni, current_session->built_private_key.get());
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for asymmetric key retrieval: " + std::to_string(mode));
                return nullptr;
            }
        }
    }

    void bridge::set_rv_public_key_sh0(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                       const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return;
        }

        auto key_data = util::byteArray_to_data(jni, key_buffer);
        if (key_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        current_session->received_public_key_0 = std::move(key_data);
    }

    jbyteArray bridge::get_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Getting nonce for session: " + std::to_string(uuid));

        switch (mode)
        {
        case static_cast<jint>(EncryptionMode::SYMMETRIC):
            {
                debug_print("[ZE] Getting symmetric nonce for session: " + std::to_string(uuid));
                if (!current_session->symmetric_nonce)
                {
                    debug_print_cerr("[ZE] No symmetric nonce set for session: " + std::to_string(uuid));
                    return nullptr;
                }
                return util::data_to_byteArray(jni, current_session->symmetric_nonce.get());
            }
        case static_cast<jint>(EncryptionMode::ASYMMETRIC):
            {
                debug_print("[ZE] Getting asymmetric nonce for session: " + std::to_string(uuid));
                if (!current_session->asymmetric_nonce)
                {
                    debug_print_cerr("[ZE] No asymmetric nonce set for session: " + std::to_string(uuid));
                    return nullptr;
                }
                return util::data_to_byteArray(jni, current_session->asymmetric_nonce.get());
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for nonce retrieval: " + std::to_string(mode));
                return nullptr;
            }
        }
    }

    jbyteArray bridge::build_hash_sh0(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                      const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building hash for session: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);
        if (message_ptr == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert message buffer to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (current_session->shared_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] No hash key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto hash = security::build_hash_using_shared_key(*current_session->shared_key_0, *message_ptr);
        if (hash == nullptr)
        {
            debug_print_cerr("[ZE] Failed to build hash for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, hash.get());
    }

    jbyteArray bridge::get_rv_public_key_sh0(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (!current_session->received_public_key_0)
        {
            debug_print_cerr("[ZE] No received public key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->received_public_key_0.get());
    }

    jbyteArray bridge::get_base_public_key_sh0(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (!current_session->shared_key_0_base.first)
        {
            debug_print_cerr("[ZE] No base public key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->shared_key_0_base.first.get());
    }

    bool bridge::compare_hash_sh0(JNIEnv *jni, [[maybe_unused]] jobject object, const jlong uuid,
                                  const jbyteArray hash_buffer,
                                  const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Comparing hash for session: " + std::to_string(uuid));

        if (message_buffer == nullptr || hash_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message or hash is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);
        const auto hash_ptr = util::byteArray_to_data(jni, hash_buffer);

        if (message_ptr == nullptr || hash_ptr == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert message or hash buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (current_session->shared_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] No hash key set for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const bool integrity = security::compare_hash(*current_session->shared_key_0, *hash_ptr, *message_ptr);

        debug_print("[ZE] Hash comparison result for session: " + std::to_string(uuid) + " - " + (integrity ? "MATCH" : "NO MATCH"));
        return integrity;
    }

    void bridge::derive_keys_sh0([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Deriving secret key for session: " + std::to_string(uuid));

        if (current_session->received_public_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] Provided public key is null for session: " + std::to_string(uuid));
            return;
        }

        if (current_session->shared_key_0_base.first == nullptr || current_session->shared_key_0_base.second == nullptr)
        {
            debug_print_cerr("[ZE] No public or private BASE key set for session: " + std::to_string(uuid));
            return;
        }

        const auto public_key = *current_session->shared_key_0_base.first;
        const auto private_key = *current_session->shared_key_0_base.second;

        std::pair<guarded_ptr, guarded_ptr> derived;

        switch (mode)
        {
        case static_cast<jint>(SideType::SERVER):
            {
                derived = security::derive_server_key(*current_session->received_public_key_0, public_key, private_key);
                break;
            }
        case static_cast<jint>(SideType::CLIENT):
            {
                derived = security::derive_client_key(*current_session->received_public_key_0, public_key, private_key);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for deriving secret key: " + std::to_string(mode));
                return;
            }
        }

        if (derived.first == nullptr || derived.second == nullptr)
        {
            debug_print_cerr("[ZE] Failed to derive keys for session: " + std::to_string(uuid));
            return;
        }

        current_session->shared_key_0_derivative = std::move(derived);
        debug_print("[ZE] Successfully derived secret key for session: " + std::to_string(uuid));
    }

    void bridge::build_base_key_sh0([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building derivable key for session: " + std::to_string(uuid));

        auto keypair = security::build_d_keypair();

        if (keypair.first == nullptr || keypair.second == nullptr)
        {
            debug_print_cerr("[ZE] Failed to build derivable keys for session: " + std::to_string(uuid));
            return;
        }

        current_session->shared_key_0_base = std::move(keypair);
        debug_print("[ZE] Successfully built derivable keys for session: " + std::to_string(uuid));
    }

    void bridge::derive_final_key_sh0([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid,
                                      const jint mode)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Deriving hash key for session: " + std::to_string(uuid));

        if (current_session->shared_key_0_derivative.first == nullptr || current_session->shared_key_0_derivative.second == nullptr)
        {
            debug_print_cerr("[ZE] Missing derived keys for session: " + std::to_string(uuid));
            return;
        }

        guarded_ptr hash_key;

        switch (mode)
        {
        case static_cast<jint>(SideType::CLIENT):
            {
                hash_key = security::derive_hash_key(*current_session->shared_key_0_derivative.second);
                break;
            }
        case static_cast<jint>(SideType::SERVER):
            {
                hash_key = security::derive_hash_key(*current_session->shared_key_0_derivative.first);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for deriving hash key: " + std::to_string(mode));
                return;
            }
        }


        if (hash_key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to derive hash key for session: " + std::to_string(uuid));
            return;
        }

        current_session->shared_key_0 = std::move(hash_key);
        debug_print("[ZE] Successfully derived hash key for session: " + std::to_string(uuid));
    }
}
