#pragma once

#include <memory>
#include <spdlog/spdlog.h>

namespace vrf
{

const std::shared_ptr<spdlog::logger> &Logger();

} // namespace vrf
