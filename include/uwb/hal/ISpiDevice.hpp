#pragma once

#include <cstddef>
#include <span>
#include "uwb/core/StatusCode.hpp"

namespace uwb::hal {

enum class SpiSpeed {
    Slow2MHz,
    Fast8MHz,
    Fast20MHz
};

class ISpiDevice {
public:
    virtual ~ISpiDevice() = default;

    virtual core::Result<void> setSpeed(SpiSpeed speed) = 0;

    /**
     * @brief Performs a full-duplex or half-duplex SPI transaction.
     * @param txHeader Command/Address header bytes to transmit
     * @param txBody Optional body bytes to transmit (can be empty)
     * @param rxBody Optional destination buffer to receive data into (can be empty)
     */
    virtual core::Result<void> transfer(
        std::span<const std::byte> txHeader,
        std::span<const std::byte> txBody,
        std::span<std::byte> rxBody) = 0;

    virtual void setChipSelect(bool active) = 0;
    virtual void wakeupPulse() = 0;
};

} // namespace uwb::hal
