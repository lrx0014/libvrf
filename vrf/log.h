// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <spdlog/spdlog.h>

namespace vrf
{

const std::shared_ptr<spdlog::logger> &Logger();

} // namespace vrf
