//
// Created by Damian Netter on 08/06/2025.
//

#pragma once
#include "ZEKit/guarded_ptr.hpp"

namespace ze_kit
{
    class session
    {
    public:
        guarded_ptr secret_key;
        guarded_ptr public_key;
        guarded_ptr shared_key;
    };
}