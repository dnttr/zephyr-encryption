//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/loader.hpp"

#include "jni.h"

#include "ZEKit/library.hpp"
#include "ZEKit/security.hpp"
#include "ZNBKit/vm_management.hpp"

const std::unordered_multimap<std::string, znb_kit::jni_bridge_reference> ze_kit::loader::methods = {
    {"x", znb_kit::jni_bridge_reference(&security::encrypt_symmetric, {})},
    {"y", znb_kit::jni_bridge_reference(&security::decrypt_symmetric, {})},
    {"z", znb_kit::jni_bridge_reference(&security::encrypt_asymmetric, {})},
    {"w", znb_kit::jni_bridge_reference(&security::decrypt_asymmetric, {})},
    {"a", znb_kit::jni_bridge_reference(&security::build_nonce_symmetric, {})},
    {"b", znb_kit::jni_bridge_reference(&security::build_nonce_asymmetric, {})},
    {"c", znb_kit::jni_bridge_reference(&security::build_key_symmetric, {})},
    {"d", znb_kit::jni_bridge_reference(&security::build_key_asymmetric, {})}
};

std::unique_ptr<znb_kit::klass_signature> ze_kit::loader::klass = nullptr;

const std::string ze_kit::loader::name = "org/dnttr/zephyr/bridge/Native";

jint JNI_OnLoad(JavaVM *jvm, void *reserved) {
    if (!ze_kit::library::initialize()) {
        std::cerr << "Failed to initialize library" << std::endl;
        return JNI_ERR;
    }

    znb_kit::vm_management::jvmti_data jvmti_data;
    jvmti_data.version = JVMTI_VERSION;
    jvmti_data.capabilities.can_get_bytecodes = true;

    ze_kit::vm_object = znb_kit::vm_management::wrap_vm(jvm, jvmti_data);

    znb_kit::jvmti_object jvmti(ze_kit::vm_object->get_env(), ze_kit::vm_object->get_jvmti()->get().get_owner());
    ze_kit::loader::klass = std::make_unique<znb_kit::klass_signature>(
        ze_kit::vm_object->get_env(), ze_kit::loader::name);

    auto [native_methods, size] = jvmti.try_mapping_methods<void>(*ze_kit::loader::klass, ze_kit::loader::methods);

    znb_kit::wrapper::register_natives(
        ze_kit::vm_object->get_env(),
        ze_kit::loader::name,
        ze_kit::loader::klass->get_owner(), native_methods);

    return JNI_VERSION_21;
}

void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    if (ze_kit::vm_object != nullptr && ze_kit::loader::klass != nullptr)
    {
        znb_kit::wrapper::unregister_natives(
            ze_kit::vm_object->get_env(),
            ze_kit::loader::name,
            ze_kit::loader::klass->get_owner());
    }
}