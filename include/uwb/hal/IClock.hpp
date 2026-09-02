#pragma once

#include <cstdint>

namespace uwb::hal {

class IClock {
public:
    virtual ~IClock() = default;

    [[nodiscard]] virtual uint64_t getMonotonicTimeUs() const noexcept = 0;
    [[nodiscard]] virtual uint64_t getMonotonicTimeMs() const noexcept = 0;
    [[nodiscard]] virtual uint32_t getCycleCount() const noexcept = 0;
    virtual void sleepMs(uint32_t milliseconds) = 0;
    virtual void busyWaitUs(uint32_t microseconds) = 0;
};

} // namespace uwb::hal
