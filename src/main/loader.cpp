//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/loader.hpp"

#include "jni.h"

#include "ZEKit/library.hpp"
#include "ZEKit/security.hpp"
#include "ZEKit/crypto_bridge/data_bridge.hpp"
#include "ZEKit/crypto_bridge/encryption_bridge.hpp"
#include "ZEKit/crypto_bridge/exchange_bridge.hpp"
#include "ZEKit/crypto_bridge/session_bridge.hpp"
#include "ZEKit/crypto_bridge/signing_bridge.hpp"
#include "ZNBKit/vm_management.hpp"

const std::unordered_multimap<std::string, znb_kit::jni_bridge_reference> ze_kit::loader::methods = {
    {"ffi_ze_create_session", znb_kit::jni_bridge_reference(&session_bridge::create_session, {})},
    {"ffi_ze_delete_session", znb_kit::jni_bridge_reference(&session_bridge::delete_session, {"long"})},
    {"ffi_ze_close_library", znb_kit::jni_bridge_reference(&session_bridge::close_library, {})},

    {"ffi_ze_encrypt_data", znb_kit::jni_bridge_reference(&encryption_bridge::encrypt_data, {"long", "byte[]", "byte[]"})},
    {"ffi_ze_decrypt_data", znb_kit::jni_bridge_reference(&encryption_bridge::decrypt_data, {"long", "byte[]", "byte[]"})},
    {"ffi_ze_encrypt_with_public_key", znb_kit::jni_bridge_reference(&encryption_bridge::encrypt_with_public_key, {"long", "byte[]"})},
    {"ffi_ze_decrypt_with_private_key", znb_kit::jni_bridge_reference(&encryption_bridge::decrypt_with_private_key, {"long", "byte[]"})},

    {"ffi_ze_generate_nonce", znb_kit::jni_bridge_reference(&data_bridge::generate_nonce, {"long", "int"})},
    {"ffi_ze_get_nonce", znb_kit::jni_bridge_reference(&data_bridge::get_nonce, {"long", "int"})},
    {"ffi_ze_set_nonce", znb_kit::jni_bridge_reference(&data_bridge::set_nonce, {"long", "int", "byte[]"})},

    {"ffi_ze_generate_keys", znb_kit::jni_bridge_reference(&data_bridge::generate_keys, {"long", "int"})},
    {"ffi_ze_get_keypair", znb_kit::jni_bridge_reference(&data_bridge::get_keypair, {"long", "int"})},

    {"ffi_ze_set_partner_public_key", znb_kit::jni_bridge_reference(&data_bridge::set_partner_public_key, {"long", "byte[]"})},

    {"ffi_ze_create_signature", znb_kit::jni_bridge_reference(&signing_bridge::create_signature, {"long", "byte[]"})},
    {"ffi_ze_verify_signature", znb_kit::jni_bridge_reference(&signing_bridge::verify_signature, {"long", "byte[]", "byte[]"})},

    {"ffi_ze_generate_signing_keypair", znb_kit::jni_bridge_reference(&signing_bridge::generate_signing_keypair, {"long"})},
    {"ffi_ze_derive_signing_keys", znb_kit::jni_bridge_reference(&signing_bridge::derive_signing_keys, {"long", "int"})},
    {"ffi_ze_finalize_signing_key", znb_kit::jni_bridge_reference(&signing_bridge::finalize_signing_key, {"long", "int"})},
    {"ffi_ze_set_signing_public_key", znb_kit::jni_bridge_reference(&signing_bridge::set_signing_public_key, {"long", "byte[]"})},
    {"ffi_ze_get_base_signing_key", znb_kit::jni_bridge_reference(&signing_bridge::get_base_signing_key, {"long"})},

    {"ffi_ze_create_key_exchange", znb_kit::jni_bridge_reference(&exchange_bridge::create_key_exchange, {"long"})},
    {"ffi_ze_process_key_exchange", znb_kit::jni_bridge_reference(&exchange_bridge::process_key_exchange, {"long", "byte[]"})}
};

const std::string ze_kit::loader::name = "org/dnttr/zephyr/network/bridge/internal/ZEKit";

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
    ze_kit::library::initialize();

    znb_kit::vm_management::jvmti_data jvmti_data;
    jvmti_data.version = JVMTI_VERSION_21;
    jvmti_data.capabilities.can_get_bytecodes = true;

    ze_kit::vm_object = znb_kit::vm_management::wrap_vm(jvm, jvmti_data);

    znb_kit::jvmti_object jvmti(ze_kit::vm_object->get_env(), ze_kit::vm_object->get_jvmti()->get().get_owner());
    const znb_kit::klass_signature *klass = new znb_kit::klass_signature(ze_kit::vm_object->get_env(), ze_kit::loader::name);

    auto [native_methods, size] = jvmti.try_mapping_methods<void>(*klass, ze_kit::loader::methods);

    znb_kit::wrapper::register_natives(
        ze_kit::vm_object->get_env(),
        ze_kit::loader::name,
        klass->get_owner(), native_methods);

    delete klass;

    return JNI_VERSION_21;
}