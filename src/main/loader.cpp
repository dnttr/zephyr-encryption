//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/loader.hpp"

#include "jni.h"
#include "ZEKit/bridge.hpp"

#include "ZEKit/library.hpp"
#include "ZEKit/security.hpp"
#include "ZNBKit/vm_management.hpp"

const std::unordered_multimap<std::string, znb_kit::jni_bridge_reference> ze_kit::loader::methods = {
    {"ffi_zm_open_session", znb_kit::jni_bridge_reference(&bridge::open_session, {})},
    {"ffi_zm_close_session", znb_kit::jni_bridge_reference(&bridge::close_session, {"long"})},
    {"ffi_ze_encrypt_symmetric", znb_kit::jni_bridge_reference(&bridge::encrypt_symmetric, {"long", "byte[]", "byte[]"})},
    {"ffi_ze_decrypt_symmetric", znb_kit::jni_bridge_reference(&bridge::decrypt_symmetric, {"long", "byte[]", "byte[]"})},
    {"ffi_ze_encrypt_asymmetric", znb_kit::jni_bridge_reference(&bridge::encrypt_asymmetric, {"long", "byte[]"})},
    {"ffi_ze_decrypt_asymmetric", znb_kit::jni_bridge_reference(&bridge::decrypt_asymmetric, {"long", "byte[]"})},
    {"ffi_ze_nonce", znb_kit::jni_bridge_reference(&bridge::build_nonce, {"long", "int"})},
    {"ffi_ze_key", znb_kit::jni_bridge_reference(&bridge::build_key, {"long", "int"})},
    {"ffi_ze_close", znb_kit::jni_bridge_reference(&bridge::close_lib, {})}
};

const std::string ze_kit::loader::name = "org/dnttr/zephyr/network/bridge/ZEKit";

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