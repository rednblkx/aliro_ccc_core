#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"
#include "uwb/hal/IClock.hpp"
#include "uwb/hal/IGpioPin.hpp"
#include "uwb/hal/ISpiDevice.hpp"

namespace uwb::transceiver {

struct TransceiverConfig {
    core::UwbChannel channel{core::UwbChannel::Channel9};
    uint16_t preambleLengthSymbols{64};
    uint8_t syncCode{9};
    core::SfdType sfd{core::SfdType::Ieee4a};
    uint16_t sfdTimeoutSymbols{65};
    uint16_t rxPacSize{8};
    uint16_t antennaDelay{0};
};

enum class StsMode : uint8_t {
    Off,
    StandardMode1,
    NoDataSp3
};

struct RxSuccessEvent {
    uint32_t rawStatusRegister{0};
    uint16_t frameLength{0};
    uint64_t rxTimestampDtu{0};
    int16_t stsQualityIndex{0};
    bool stsPassed{false};
};

class ITransceiverListener {
public:
    virtual ~ITransceiverListener() = default;
    virtual void onRxSuccess(const RxSuccessEvent& event) = 0;
    virtual void onRxTimeout() = 0;
    virtual void onRxError(uint32_t errorStatus) = 0;
    virtual void onTxComplete() = 0;
};

class DW3000Controller {
public:
    DW3000Controller(
        hal::ISpiDevice& spi,
        hal::IGpioPin& irqPin,
        hal::IGpioPin& resetPin,
        hal::IClock& clock);
    ~DW3000Controller();

    [[nodiscard]] core::Result<void> initialize();
    [[nodiscard]] core::Result<void> configurePhy(const TransceiverConfig& config);

    // Fast-path Dynamic STS Management
    [[nodiscard]] core::Result<void> loadStsKey(std::span<const std::byte, 16> key);
    [[nodiscard]] core::Result<void> loadStsIv(std::span<const std::byte, 16> iv);
    [[nodiscard]] core::Result<void> configureStsMode(StsMode mode);

    // Precision Timed Scheduling
    // rangingFrame=true sends an SP3 (STS no-data) RFRAME: a 4-byte dummy payload is
    // loaded with the ranging bit set so the DW3000 radiates the STS segment.
    [[nodiscard]] core::Result<void> startDelayedTx(uint32_t txStartTimeDtu, std::span<const std::byte> frameData, bool rangingFrame = false);
    [[nodiscard]] core::Result<void> startDelayedRx(uint32_t rxStartTimeDtu, uint16_t timeoutDtu);
    [[nodiscard]] core::Result<void> startImmediateRx(uint16_t timeoutDtu = 0);
    void forceReceiverOff();

    // Timestamp & Data Ingestion
    [[nodiscard]] uint64_t readRxTimestampDtu();
    [[nodiscard]] uint64_t readTxTimestampDtu();
    [[nodiscard]] uint32_t readSystemTimestampDtu();
    [[nodiscard]] uint32_t readSysStatusLo() const;
    [[nodiscard]] core::Result<size_t> readReceivedData(std::span<std::byte> outBuffer, uint16_t offset = 0);

    void setListener(ITransceiverListener* listener) noexcept { m_listener = listener; }

    // Direct driver callback handlers
    void handleDriverRxSuccess(uint32_t status, uint16_t dataLength);
    void handleDriverTxDone();
    void handleDriverRxTimeout();
    void handleDriverRxError(uint32_t errorStatus);

    void processInterrupt();

private:
    hal::ISpiDevice& m_spi;
    hal::IGpioPin& m_irqPin;
    hal::IGpioPin& m_resetPin;
    hal::IClock& m_clock;
    ITransceiverListener* m_listener{nullptr};
    bool m_initialized{false};

    void performHardwareReset();
};

} // namespace uwb::transceiver