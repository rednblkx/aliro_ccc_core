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

// Phase Difference of Arrival mode. Off for single-antenna parts; Mode3 (dual-RX
// simultaneous STS accumulation) is the DW3220 dual-antenna AoA mode.
enum class PdoaMode : uint8_t {
    Off,
    Mode1,
    Mode3
};

struct TransceiverConfig {
    core::UwbChannel channel{core::UwbChannel::Channel9};
    uint16_t preambleLengthSymbols{64};
    uint8_t syncCode{9};
    core::SfdType sfd{core::SfdType::Ieee4a};
    uint16_t sfdTimeoutSymbols{65};
    uint16_t rxPacSize{8};
    uint16_t antennaDelay{0};
    PdoaMode pdoa{PdoaMode::Off};
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
    // Raw PDoA measurement (signed Q11 fixed point, radians). Only valid when the
    // transceiver was configured with a PdoaMode other than Off.
    int16_t pdoaRaw{0};
    bool pdoaValid{false};
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
    // Combined key+IV load: one contiguous 32-byte register write + LOAD_IV strobe
    // (2 SPI transactions instead of 10) — use on every arm path.
    [[nodiscard]] core::Result<void> loadStsKeyIv(std::span<const std::byte, 16> key, std::span<const std::byte, 16> iv);
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

    // First-path-power NLOS input: reads the STS0 accumulator diagnostics
    // (F1/F2/F3, CIR power, accumulation count) via per-register reads and
    // converts them to Q8.8 dBm first-path power and total channel power (RSSI).
    // Call after an RX event, off the arm critical path; valid=false when the
    // diagnostics are unreadable or degenerate. Returns SHRT_MIN (Q8.8 -128 dB)
    // in both power fields when !valid.
    struct FirstPathDiagnostics {
        int16_t firstPathPowerDbQ8{INT16_MIN};
        int16_t rssiDbQ8{INT16_MIN};
        bool valid{false};
    };
    [[nodiscard]] FirstPathDiagnostics readFinalFirstPathDiagnostics();

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

private:
    hal::ISpiDevice& m_spi;
    hal::IGpioPin& m_irqPin;
    hal::IGpioPin& m_resetPin;
    hal::IClock& m_clock;
    ITransceiverListener* m_listener{nullptr};
    bool m_initialized{false};
    bool m_pdoaEnabled{false};

    void performHardwareReset();
};

} // namespace uwb::transceiver