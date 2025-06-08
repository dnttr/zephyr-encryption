//
// Created by Damian Netter on 08/06/2025.
//

#pragma once

#include <unordered_map>

#include "ZNBKit/vm_object.hpp"

namespace ze_kit
{
    static std::unique_ptr<znb_kit::vm_object> vm_object;

    class loader
    {
    public:
        static const std::unordered_multimap<std::string, znb_kit::jni_bridge_reference> methods;
        static const std::string name;
    };
}
