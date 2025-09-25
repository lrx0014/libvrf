#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace
{

class LoggerManager
{
  public:
    LoggerManager()
    {
        logger_ = spdlog::stdout_color_mt("vrf");
        auto formatter = std::make_unique<spdlog::pattern_formatter>("[%t] %Y-%m-%d %H:%M:%S.%e | %l: %v");
        logger_->set_formatter(std::move(formatter));
    }

    ~LoggerManager()
    {
        logger_->flush();
        spdlog::drop("vrf");
        logger_ = nullptr;
    }

    [[nodiscard]] const std::shared_ptr<spdlog::logger> &get_logger() const
    {
        return logger_;
    }

  private:
    std::shared_ptr<spdlog::logger> logger_;
};

} // namespace

namespace vrf
{

const std::shared_ptr<spdlog::logger> &Logger()
{
    static auto logger = LoggerManager();
    return logger.get_logger();
}

} // namespace vrf
