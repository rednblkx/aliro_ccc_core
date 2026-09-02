#pragma once

#include <functional>
#include "uwb/core/StatusCode.hpp"

namespace uwb::hal {

enum class PinMode {
    Input,
    OutputPushPull,
    OutputOpenDrain
};

enum class InterruptTrigger {
    RisingEdge,
    FallingEdge,
    BothEdges
};

class IGpioPin {
public:
    virtual ~IGpioPin() = default;

    virtual core::Result<void> setMode(PinMode mode) = 0;
    virtual void write(bool high) = 0;
    virtual bool read() const = 0;

    using InterruptCallback = std::function<void()>;
    virtual core::Result<void> attachInterrupt(InterruptTrigger trigger, InterruptCallback callback) = 0;
    virtual void enableInterrupt() = 0;
    virtual void disableInterrupt() = 0;
};

} // namespace uwb::hal
