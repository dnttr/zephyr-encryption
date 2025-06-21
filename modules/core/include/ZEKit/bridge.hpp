//
// Created by Damian Netter on 08/06/2025.
//

#pragma once

#include <ZNBKit/debug.hpp>
#include <ZNBKit/internal/wrapper.hpp>
#include <ZNBKit/vm/vm_management.hpp>

#include "ZEKit/library.hpp"
#include "ZEKit/security.hpp"

namespace ze_kit
{

#define DEFAULT JNIEnv *jni, jobject object
#define UUID jlong uuid

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

    inline bool validate_session(const uint64_t uuid, const bool log_error = true)
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
