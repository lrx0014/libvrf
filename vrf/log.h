// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace vrf
{

enum class LogLevel : std::size_t
{
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    IGNORE,
};

constexpr std::size_t log_level_count = static_cast<std::size_t>(LogLevel::IGNORE);

using log_handler_t = std::function<void(std::string)>;

using flush_handler_t = std::function<void()>;

using close_handler_t = std::function<void()>;

class Logger
{
  public:
    static std::shared_ptr<Logger> Create(std::array<log_handler_t, log_level_count> log_handlers,
                                          std::array<flush_handler_t, log_level_count> flush_handlers,
                                          std::array<close_handler_t, log_level_count> close_handlers)
    {
        return std::shared_ptr<Logger>(
            new Logger(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers)));
    }

    ~Logger()
    {
        std::lock_guard<std::mutex> lock{mtx_};
        close_internal();
    }

    void flush() const
    {
        std::lock_guard<std::mutex> lock{mtx_};
        flush_internal();
    }

    void close()
    {
        std::lock_guard<std::mutex> lock{mtx_};
        close_internal();
    }

    LogLevel get_level() const
    {
        std::lock_guard<std::mutex> lock{mtx_};
        return log_level_;
    }

    void set_level(LogLevel level)
    {
        std::lock_guard<std::mutex> lock{mtx_};
        log_level_ = level;
    }

    void log(LogLevel level, std::string msg) const;

    template <typename... Args> void log(LogLevel level, std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(level, std::format(fmt_str, std::forward<Args>(args)...));
    }

    template <typename... Args> void trace(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::TRACE, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args> void debug(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::DEBUG, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args> void info(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::INFO, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args> void warn(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::WARN, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args> void error(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::ERROR, fmt_str, std::forward<Args>(args)...);
    }

  private:
    Logger(std::array<log_handler_t, log_level_count> log_handlers,
           std::array<flush_handler_t, log_level_count> flush_handlers,
           std::array<close_handler_t, log_level_count> close_handlers)
        : log_handlers_{std::move(log_handlers)}, flush_handlers_{std::move(flush_handlers)},
          close_handlers_{std::move(close_handlers)} {};

    Logger(const Logger &) = delete;

    Logger &operator=(const Logger &) = delete;

    void flush_internal() const;

    void close_internal();

    mutable std::mutex mtx_;

    LogLevel log_level_ = LogLevel::INFO;

    std::array<log_handler_t, log_level_count> log_handlers_{};

    std::array<flush_handler_t, log_level_count> flush_handlers_{};

    std::array<close_handler_t, log_level_count> close_handlers_{};
};

std::shared_ptr<Logger> NewDefaultLogger();

std::shared_ptr<Logger> &GetOrSetLogger(std::shared_ptr<Logger> new_logger);

inline std::shared_ptr<Logger> GetLogger()
{
    return GetOrSetLogger(nullptr);
}

} // namespace vrf
