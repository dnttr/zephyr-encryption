//
// Created by Damian Netter on 15/06/2025.
//

#include "ZEKit/crypto_bridge/session_bridge.hpp"

#include <sodium/randombytes.h>

#include "ZEKit/loader.hpp"

namespace ze_kit
{
    void session_bridge::close_library(JNIEnv *jni, [[maybe_unused]] jobject object)
    {
        znb_kit::wrapper::unregister_natives(jni, loader::name);
        znb_kit::wrapper::check_for_corruption();
    }

    jlong session_bridge::create_session([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject object)
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

    jint session_bridge::delete_session([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
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
}
