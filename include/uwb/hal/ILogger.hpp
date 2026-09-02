#pragma once

#include <string_view>

namespace uwb::hal {

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error
};

class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(LogLevel level, std::string_view component, std::string_view message) = 0;
};

} // namespace uwb::hal
