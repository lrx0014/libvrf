#pragma once

#include <memory>
#include <spdlog/spdlog.h>

// NOT A PUBLIC HEADER

namespace vrf
{

const std::shared_ptr<spdlog::logger> &Logger();

} // namespace vrf
