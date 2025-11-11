// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/log.h"
#include <iostream>

namespace vrf
{

std::shared_ptr<Logger> NewDefaultLogger()
{
    std::array<log_handler_t, log_level_count> log_handlers{};
    log_handlers[static_cast<std::size_t>(LogLevel::TRACE)] = [](std::string msg) {
        std::cout << "[trace] " << msg << '\n';
    };
    log_handlers[static_cast<std::size_t>(LogLevel::DEBUG)] = [](std::string msg) {
        std::cout << "[debug] " << msg << '\n';
    };
    log_handlers[static_cast<std::size_t>(LogLevel::INFO)] = [](std::string msg) {
        std::cout << "[info] " << msg << '\n';
    };
    log_handlers[static_cast<std::size_t>(LogLevel::WARN)] = [](std::string msg) {
        std::cerr << "[warning] " << msg << '\n';
    };
    log_handlers[static_cast<std::size_t>(LogLevel::ERROR)] = [](std::string msg) {
        std::cerr << "[error] " << msg << '\n';
    };

    std::array<flush_handler_t, log_level_count> flush_handlers{};
    flush_handlers[static_cast<std::size_t>(LogLevel::TRACE)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(LogLevel::DEBUG)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(LogLevel::INFO)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(LogLevel::WARN)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(LogLevel::ERROR)] = []() { std::cerr << std::flush; };

    // No special close actions needed for stdout/stderr.
    std::array<close_handler_t, log_level_count> close_handlers{};

    return Logger::Create(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
}

} // namespace vrf
