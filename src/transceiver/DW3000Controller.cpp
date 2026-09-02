#include "uwb/transceiver/DW3000Controller.hpp"
#include <array>
#include <cstring>

extern "C" {
#include "deca_device_api.h"
#include "deca_interface.h"

extern const struct dwt_driver_s dw3000_driver;

extern struct dwt_probe_s s_probeInterface;
}

namespace uwb::transceiver {

namespace {

DW3000Controller* s_activeController = nullptr;
hal::ISpiDevice* s_activeSpi = nullptr;

std::array<std::byte, 16> s_lastStsKey{};
bool s_stsKeyValid = false;

int32_t decaReadFromSpi(uint16_t headerLength, uint8_t* headerBuffer, uint16_t readLength, uint8_t* readBuffer) {
    if (!s_activeSpi) return -1;
    auto res = s_activeSpi->transfer(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(headerBuffer), headerLength),
        {},
        std::span<std::byte>(reinterpret_cast<std::byte*>(readBuffer), readLength)
    );
    return res.has_value() ? 0 : -1;
}

int32_t decaWriteToSpi(uint16_t headerLength, const uint8_t* headerBuffer, uint16_t bodyLength, const uint8_t* bodyBuffer) {
    if (!s_activeSpi) return -1;
    auto res = s_activeSpi->transfer(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(headerBuffer), headerLength),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(bodyBuffer), bodyLength),
        {}
    );
    return res.has_value() ? 0 : -1;
}

int32_t decaWriteToSpiWithCrc(uint16_t headerLength, const uint8_t* headerBuffer, uint16_t bodyLength, const uint8_t* bodyBuffer, uint8_t crc8) {
    (void)crc8;
    return decaWriteToSpi(headerLength, headerBuffer, bodyLength, bodyBuffer);
}

void decaSetSlowRate() {
    if (s_activeSpi) (void)s_activeSpi->setSpeed(hal::SpiSpeed::Slow2MHz);
}

void decaSetFastRate() {
    if (s_activeSpi) (void)s_activeSpi->setSpeed(hal::SpiSpeed::Fast8MHz);
}

void decaWakeupDevice() {
    if (s_activeSpi) s_activeSpi->wakeupPulse();
}

constexpr struct dwt_spi_s s_decaSpiFunctions = {
    .readfromspi = decaReadFromSpi,
    .writetospi = decaWriteToSpi,
    .writetospiwithcrc = decaWriteToSpiWithCrc,
    .setslowrate = decaSetSlowRate,
    .setfastrate = decaSetFastRate
};

const struct dwt_driver_s* s_driverList[] = { &dw3000_driver };

void decaRxSuccessCallback(const dwt_cb_data_t* cbData) {
    if (s_activeController) {
        const uint32_t status = cbData ? cbData->status : 0;
        const uint16_t len = cbData ? cbData->datalength : 0;
        s_activeController->handleDriverRxSuccess(status, len);
    }
}

void decaRxTimeoutCallback(const dwt_cb_data_t* cbData) {
    (void)cbData;
    if (s_activeController) s_activeController->handleDriverRxTimeout();
}

void decaRxErrorCallback(const dwt_cb_data_t* cbData) {
    if (s_activeController) {
        s_activeController->handleDriverRxError(cbData ? cbData->status : 0);
    }
}

void decaTxDoneCallback(const dwt_cb_data_t* cbData) {
    (void)cbData;
    if (s_activeController) s_activeController->handleDriverTxDone();
}

} // namespace

} // namespace uwb::transceiver

extern "C" {
struct dwt_probe_s s_probeInterface = {
    .dw = nullptr,
    .spi = const_cast<struct dwt_spi_s*>(&uwb::transceiver::s_decaSpiFunctions),
    .wakeup_device_with_io = uwb::transceiver::decaWakeupDevice,
    .driver_list = const_cast<struct dwt_driver_s**>(uwb::transceiver::s_driverList),
    .dw_driver_num = 1
};
}

namespace uwb::transceiver {

DW3000Controller::DW3000Controller(
    hal::ISpiDevice& spi,
    hal::IGpioPin& irqPin,
    hal::IGpioPin& resetPin,
    hal::IClock& clock)
    : m_spi(spi), m_irqPin(irqPin), m_resetPin(resetPin), m_clock(clock) {
    s_activeController = this;
    s_activeSpi = &m_spi;
}

DW3000Controller::~DW3000Controller() {
    if (s_activeController == this) {
        s_activeController = nullptr;
        s_activeSpi = nullptr;
    }
}

void DW3000Controller::performHardwareReset() {
    (void)m_resetPin.setMode(hal::PinMode::OutputPushPull);
    m_resetPin.write(false);
    m_clock.sleepMs(2);
    (void)m_resetPin.setMode(hal::PinMode::Input);
    m_clock.sleepMs(5);
}

core::Result<void> DW3000Controller::initialize() {
    performHardwareReset();
    if (dwt_probe(&s_probeInterface) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::TransceiverError);
    }
    if (dwt_initialise(DWT_DW_INIT) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::TransceiverError);
    }
    dwt_callbacks_s callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.cbTxDone = decaTxDoneCallback;
    callbacks.cbRxOk = decaRxSuccessCallback;
    callbacks.cbRxTo = decaRxTimeoutCallback;
    callbacks.cbRxErr = decaRxErrorCallback;
    dwt_setcallbacks(&callbacks);

    dwt_setinterrupt(
    DWT_INT_RXFCG_BIT_MASK | DWT_INT_RXFR_BIT_MASK | DWT_INT_RXFCE_BIT_MASK |
                     DWT_INT_RXFTO_BIT_MASK | DWT_INT_RXPTO_BIT_MASK |
                     DWT_INT_RXPHE_BIT_MASK | DWT_INT_RXSTO_BIT_MASK |
                     DWT_INT_RXFSL_BIT_MASK | DWT_INT_ARFE_BIT_MASK |
                     DWT_INT_TXFRS_BIT_MASK,
                 0u, DWT_ENABLE_INT );
    m_initialized = true;
    return {};
}

core::Result<void> DW3000Controller::configurePhy(const TransceiverConfig& config) {
    if (!m_initialized) {
        return std::unexpected(core::StatusCode::InvalidState);
    }

    dwt_forcetrxoff();

    const uint8_t chan = (config.channel == core::UwbChannel::Channel5) ? 5 : 9;
    const uint8_t code = (config.syncCode >= 9 && config.syncCode <= 12) ? config.syncCode : 9;

    dwt_config_t decaConfig;
    std::memset(&decaConfig, 0, sizeof(decaConfig));
    decaConfig.chan = chan;
    decaConfig.txPreambLength = (config.preambleLengthSymbols == 64) ? DWT_PLEN_64 : DWT_PLEN_128;
    decaConfig.rxPAC = DWT_PAC8;
    decaConfig.txCode = code;
    decaConfig.rxCode = code;
    decaConfig.sfdType = (config.sfd == core::SfdType::Ieee4a) ? DWT_SFD_IEEE_4A : DWT_SFD_IEEE_4Z;
    decaConfig.dataRate = DWT_BR_6M8;
    decaConfig.phrMode = DWT_PHRMODE_STD;
    decaConfig.phrRate = DWT_PHRRATE_STD;
    decaConfig.sfdTO = (config.sfdTimeoutSymbols > 0) ? config.sfdTimeoutSymbols : (64 + 1);
    decaConfig.stsMode = DWT_STS_MODE_OFF;
    decaConfig.stsLength = DWT_STS_LEN_64;
    decaConfig.pdoaMode = DWT_PDOA_M0;

    if (dwt_configure(&decaConfig) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::TransceiverError);
    }
    s_stsKeyValid = false;

    dwt_txconfig_t txConfig;
    std::memset(&txConfig, 0, sizeof(txConfig));
    txConfig.PGdly = 0x34;
    txConfig.power = 0xfdfdfdfdUL;
    txConfig.PGcount = 0;
    dwt_configuretxrf(&txConfig);

    // Antenna delay: leave the CIA_CONF/TX_ANTD reset defaults (16384 DTU) unless a
    // calibration value is configured — the CIA adjusted-ToA pipeline is calibrated
    // around the defaults, and zeroing them biases DS-TWR by ~+76.7 m (65536 DTU).
    if (config.antennaDelay != 0) {
        dwt_setrxantennadelay(config.antennaDelay);
        dwt_settxantennadelay(config.antennaDelay);
    }

    return {};
}

void DW3000Controller::handleDriverRxSuccess(uint32_t status, uint16_t dataLength) {
    if (m_listener) {
        int16_t stsQuality = 0;
        const int qRet = dwt_readstsquality(&stsQuality, 0);
        const uint32_t st = (status != 0) ? status : dwt_readsysstatuslo();
        const uint16_t len = (dataLength != 0) ? dataLength : dwt_getframelength(nullptr);

        RxSuccessEvent ev{
            .rawStatusRegister = st,
            .frameLength = len,
            .rxTimestampDtu = readRxTimestampDtu(),
            .stsQualityIndex = stsQuality,
            // Only CPERR (STS counter/quality failure) disqualifies a frame. RXFCE is set
            // by the driver on every SP3 no-data reception as its "no payload" marker and
            // must not be treated as an error here.
            .stsPassed = (qRet >= 0 && (st & DWT_INT_CPERR_BIT_MASK) == 0)
        };
        m_listener->onRxSuccess(ev);
    }
}

void DW3000Controller::handleDriverTxDone() {
    if (m_listener) m_listener->onTxComplete();
}

void DW3000Controller::handleDriverRxTimeout() {
    if (m_listener) m_listener->onRxTimeout();
}

void DW3000Controller::handleDriverRxError(uint32_t errorStatus) {
    if (m_listener) m_listener->onRxError(errorStatus);
}

namespace {
template <typename RegImage>
void packStsRegister(RegImage& out, std::span<const std::byte, 16> bytes) {
    std::array<std::byte, 16> rev{};
    for (size_t i = 0; i < 16; ++i) {
        rev[i] = bytes[15 - i];
    }
    std::memcpy(&out, rev.data(), 16);
}
} // namespace

core::Result<void> DW3000Controller::loadStsKey(std::span<const std::byte, 16> key) {
    if (s_stsKeyValid && std::equal(key.begin(), key.end(), s_lastStsKey.begin())) {
        return {};
    }
    dwt_sts_cp_key_t decaKey;
    packStsRegister(decaKey, key);
    dwt_configurestskey(&decaKey);
    std::memcpy(s_lastStsKey.data(), key.data(), 16);
    s_stsKeyValid = true;
    return {};
}

core::Result<void> DW3000Controller::loadStsIv(std::span<const std::byte, 16> iv) {
    dwt_sts_cp_iv_t decaIv;
    packStsRegister(decaIv, iv);
    dwt_configurestsiv(&decaIv);
    dwt_configurestsloadiv();
    return {};
}

core::Result<void> DW3000Controller::configureStsMode(StsMode mode) {
    uint8_t m = DWT_STS_MODE_OFF;
    if (mode == StsMode::StandardMode1) m = DWT_STS_MODE_1;
    else if (mode == StsMode::NoDataSp3) m = DWT_STS_MODE_ND;

    dwt_configurestsmode(m);
    return {};
}

static void clearHpdwarn() {
    dwt_writesysstatuslo(DWT_INT_HPDWARN_BIT_MASK);
}

core::Result<void> DW3000Controller::startDelayedTx(uint32_t txStartTimeDtu, std::span<const std::byte> frameData, bool rangingFrame) {
    clearHpdwarn();
    dwt_setdelayedtrxtime(txStartTimeDtu);
    if (!frameData.empty()) {
        dwt_writetxdata(static_cast<uint16_t>(frameData.size()),
                        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(frameData.data())), 0);
        dwt_writetxfctrl(static_cast<uint16_t>(frameData.size() + 2), 0, 1);
    } else if (rangingFrame) {
        static const std::array<std::byte, 4> kDummyPayload{};
        dwt_writetxdata(static_cast<uint16_t>(kDummyPayload.size()),
                        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(kDummyPayload.data())), 0);
        dwt_writetxfctrl(static_cast<uint16_t>(kDummyPayload.size() + 2), 0, 1);
    } else {
        // SP0 frame with no payload (should not occur)
        dwt_writetxfctrl(0, 0, 0);
    }
    if (dwt_starttx(DWT_START_TX_DELAYED) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::LateTransmission);
    }
    return {};
}

core::Result<void> DW3000Controller::startDelayedRx(uint32_t rxStartTimeDtu, uint16_t timeoutDtu) {
    clearHpdwarn();
    dwt_setdelayedtrxtime(rxStartTimeDtu);
    dwt_setrxtimeout(timeoutDtu);

    if (dwt_rxenable(DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::LateTransmission);
    }
    return {};
}

core::Result<void> DW3000Controller::startImmediateRx(uint16_t timeoutDtu) {
    dwt_setrxtimeout(timeoutDtu);
    if (dwt_rxenable(DWT_START_RX_IMMEDIATE) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::TransceiverError);
    }
    return {};
}

void DW3000Controller::forceReceiverOff() {
    dwt_forcetrxoff();
}

uint64_t DW3000Controller::readRxTimestampDtu() {
    uint8_t ts[5] = {0};
    dwt_readrxtimestamp_ipatov(ts);
    return static_cast<uint64_t>(ts[0]) |
          (static_cast<uint64_t>(ts[1]) << 8) |
          (static_cast<uint64_t>(ts[2]) << 16) |
          (static_cast<uint64_t>(ts[3]) << 24) |
          (static_cast<uint64_t>(ts[4]) << 32);
}

uint64_t DW3000Controller::readTxTimestampDtu() {
    uint8_t ts[5] = {0};
    dwt_readtxtimestamp(ts);
    return static_cast<uint64_t>(ts[0]) |
          (static_cast<uint64_t>(ts[1]) << 8) |
          (static_cast<uint64_t>(ts[2]) << 16) |
          (static_cast<uint64_t>(ts[3]) << 24) |
          (static_cast<uint64_t>(ts[4]) << 32);
}

uint32_t DW3000Controller::readSystemTimestampDtu() {
    return dwt_readsystimestamphi32();
}

uint32_t DW3000Controller::readSysStatusLo() const {
    return dwt_readsysstatuslo();
}

core::Result<size_t> DW3000Controller::readReceivedData(std::span<std::byte> outBuffer, uint16_t offset) {
    uint8_t rng = 0;
    uint16_t frameLen = dwt_getframelength(&rng);
    if (frameLen == 0) {
        frameLen = static_cast<uint16_t>(outBuffer.size());
    }
    if (outBuffer.size() < frameLen) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    dwt_readrxdata(reinterpret_cast<uint8_t*>(outBuffer.data()), frameLen, offset);
    return frameLen;
}

void DW3000Controller::processInterrupt() {
    const uint32_t status = dwt_readsysstatuslo();
    if (status == 0 || status == 0xFFFFFFFF) {
        return;
    }

    // Always clear all active status bits on the transceiver to un-assert IRQ line
    dwt_writesysstatuslo(status);

    if (status & DWT_INT_TXFRS_BIT_MASK) {
        if (m_listener) m_listener->onTxComplete();
        return;
    }

    constexpr uint32_t RxFrameEventsMask = DWT_INT_RXFCG_BIT_MASK | DWT_INT_RXFCE_BIT_MASK | 0x00001000UL /* RXPHD */;
    if (status & RxFrameEventsMask) {
        if (m_listener) {
            uint8_t rng = 0;
            const uint16_t len = dwt_getframelength(&rng);
            int16_t stsQuality = 0;
            const int qRet = dwt_readstsquality(&stsQuality, 0);

            RxSuccessEvent ev{
                .rawStatusRegister = status,
                .frameLength = len,
                .rxTimestampDtu = readRxTimestampDtu(),
                .stsQualityIndex = stsQuality,
                .stsPassed = (qRet >= 0 && (status & 0x10000000U) == 0 && (status & DWT_INT_RXFCE_BIT_MASK) == 0)
            };
            m_listener->onRxSuccess(ev);
        }
        return;
    }

    if (status & (DWT_INT_RXFTO_BIT_MASK | DWT_INT_RXPTO_BIT_MASK | DWT_INT_RXSTO_BIT_MASK)) {
        if (m_listener) m_listener->onRxTimeout();
        return;
    }

    if (status & (DWT_INT_RXPHE_BIT_MASK | DWT_INT_ARFE_BIT_MASK)) {
        if (m_listener) m_listener->onRxError(status);
        return;
    }
    if (status & (DWT_INT_RXPHE_BIT_MASK | DWT_INT_ARFE_BIT_MASK | DWT_INT_RXFSL_BIT_MASK)) {
        if (m_listener) m_listener->onRxError(status);
        return;
    }
}
} // namespace uwb::transceiver