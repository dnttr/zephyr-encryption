//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include <memory>

#include "data.hpp"

namespace ze_kit
{
    class guarded_ptr : public std::unique_ptr<data, void *(*)(data *)>
    {
    };
}
