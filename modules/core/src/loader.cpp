//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/loader.hpp"

#include <jni.h>
#include <ZNBKit/vm/vm_management.hpp>

#include "ZEKit/library.hpp"
#include "ZEKit/security.hpp"
#include "ZEKit/internal/data_bridge.hpp"
#include "ZEKit/internal/encryption_bridge.hpp"
#include "ZEKit/internal/exchange_bridge.hpp"
#include "ZEKit/internal/session_bridge.hpp"
#include "ZEKit/internal/signing_bridge.hpp"

using znb_kit::jni_bridge_reference;

using znb_kit::LONG;
using znb_kit::INT;
using znb_kit::BYTE_ARRAY;

const std::unordered_multimap<std::string, jni_bridge_reference> ze_kit::loader::methods = {
    // Session Management
    {"ffi_ze_create_session", jni_bridge_reference(&session_bridge::create_session)},
    {"ffi_ze_delete_session", jni_bridge_reference(&session_bridge::delete_session, { LONG })},
    {"ffi_ze_close_library", jni_bridge_reference(&session_bridge::close_library)},

    // Key Exchange
    {"ffi_ze_create_key_exchange", jni_bridge_reference(&exchange_bridge::create_key_exchange, { LONG })},
    {"ffi_ze_process_key_exchange", jni_bridge_reference(&exchange_bridge::process_key_exchange, { LONG, BYTE_ARRAY })},

    // Encryption & Decryption
    {"ffi_ze_encrypt_data", jni_bridge_reference(&encryption_bridge::encrypt_data, { LONG, BYTE_ARRAY, BYTE_ARRAY })},
    {"ffi_ze_decrypt_data", jni_bridge_reference(&encryption_bridge::decrypt_data, { LONG, BYTE_ARRAY, BYTE_ARRAY })},
    {"ffi_ze_encrypt_with_public_key", jni_bridge_reference(&encryption_bridge::encrypt_with_public_key, { LONG, BYTE_ARRAY })},
    {"ffi_ze_decrypt_with_private_key", jni_bridge_reference(&encryption_bridge::decrypt_with_private_key, { LONG, BYTE_ARRAY })},

    // Signing & Verification
    {"ffi_ze_create_signature", jni_bridge_reference(&signing_bridge::create_signature, { LONG, BYTE_ARRAY })},
    {"ffi_ze_verify_signature", jni_bridge_reference(&signing_bridge::verify_signature, { LONG, BYTE_ARRAY, BYTE_ARRAY })},

    // Key & Nonce Management
    {"ffi_ze_generate_keys", jni_bridge_reference(&data_bridge::generate_keys, { LONG, INT })},
    {"ffi_ze_get_keypair", jni_bridge_reference(&data_bridge::get_keypair, { LONG, INT })},
    {"ffi_ze_set_partner_public_key", jni_bridge_reference(&data_bridge::set_partner_public_key, { LONG, BYTE_ARRAY })},
    {"ffi_ze_generate_signing_keypair", jni_bridge_reference(&signing_bridge::generate_signing_keypair, { LONG })},
    {"ffi_ze_derive_signing_keys", jni_bridge_reference(&signing_bridge::derive_signing_keys, { LONG, INT })},
    {"ffi_ze_finalize_signing_key", jni_bridge_reference(&signing_bridge::finalize_signing_key, { LONG, INT })},
    {"ffi_ze_set_signing_public_key", jni_bridge_reference(&signing_bridge::set_signing_public_key, { LONG, BYTE_ARRAY })},
    {"ffi_ze_get_base_signing_key", jni_bridge_reference(&signing_bridge::get_base_signing_key, { LONG })},
    {"ffi_ze_generate_nonce", jni_bridge_reference(&data_bridge::generate_nonce, { LONG, INT })},
    {"ffi_ze_get_nonce", jni_bridge_reference(&data_bridge::get_nonce, { LONG, INT })},
    {"ffi_ze_set_nonce", jni_bridge_reference(&data_bridge::set_nonce, { LONG, INT, BYTE_ARRAY })},
};

//TODO: make it more dynamic. It should be possible to load the class name from a configuration file or similar.
const std::string ze_kit::loader::name = "org/dnttr/zephyr/bridge/internal/ZEKit";

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    ze_kit::library::initialize();

    znb_kit::vm_management::jvmti_data jvmti_data;
    jvmti_data.version = JVMTI_VERSION_21;
    jvmti_data.capabilities.can_get_bytecodes = true;

    ze_kit::vm_object = znb_kit::vm_management::wrap_vm(vm, jvmti_data);

    znb_kit::jvmti_object jvmti(ze_kit::vm_object->get_env(), ze_kit::vm_object->get_jvmti()->get().get_owner());

    const znb_kit::klass_signature klass(ze_kit::vm_object->get_env(), ze_kit::loader::name);

    auto [native_methods, size] = jvmti.try_mapping_methods<void>(klass, ze_kit::loader::methods);

    znb_kit::wrapper::register_natives(
        ze_kit::vm_object->get_env(),
        ze_kit::loader::name,
        klass.get_owner(), native_methods);

    return JNI_VERSION_21;
}