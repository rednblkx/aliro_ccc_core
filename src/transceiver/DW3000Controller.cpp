#include "uwb/transceiver/DW3000Controller.hpp"
#include <array>
#include <cstring>

extern "C" {
#include "deca_device_api.h"
#include "deca_interface.h"
#include "deca_private.h"
#include "dw3000/dw3000_deca_regs.h"

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
    switch (config.pdoa) {
        case PdoaMode::Mode1:
            decaConfig.pdoaMode = DWT_PDOA_M1;
            break;
        case PdoaMode::Mode3:
            // DW3220 dual-antenna AoA mode: simultaneous STS accumulation on both RX ports
            decaConfig.pdoaMode = DWT_PDOA_M3;
            break;
        case PdoaMode::Off:
        default:
            decaConfig.pdoaMode = DWT_PDOA_M0;
            break;
    }
    m_pdoaEnabled = (config.pdoa != PdoaMode::Off);

    if (dwt_configure(&decaConfig) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::TransceiverError);
    }
    s_stsKeyValid = false;

#ifdef CONFIG_UWB_NLOS_ENABLE
    // dwt_configure resets the CIA diagnostic logging config each time, and the
    // diagnostic registers read 0 unless logging is re-armed to ALL — required
    // for dwt_nlos_alldiag and the power calculations to see real values.
    dwt_configciadiag(DW_CIA_DIAG_LOG_ALL);
#endif

    // Permanently enable the frame-wait timeout: RX_FWTO==0 disables it at runtime, and
    // every ranging arm programs a nonzero RX_FWTO. Setting the SYS_CFG.RXWTOE bit once
    // here lets startDelayedRx/startDelayedTx skip the per-arm read-modify-write of
    // SYS_CFG (one fewer SPI transaction inside the arm deadline). Note dwt_configure
    // rewrites SYS_CFG (PHR/STS/PDOA bits), so this must come after it.
    {
        uint8_t sysCfg[4] = {0};
        dwt_readfromdevice(SYS_CFG_ID, 0U, 4U, sysCfg);
        sysCfg[1] |= static_cast<uint8_t>((SYS_CFG_RXWTOE_BIT_MASK >> 8U) & 0xFFU);
        dwt_writetodevice(SYS_CFG_ID, 0U, 4U, sysCfg);
    }

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

        // PDoA is a single 2-byte SPI read (~10 µs) — safe on the arm critical path
        int16_t pdoaRaw = 0;
        bool pdoaValid = false;
        if (m_pdoaEnabled) {
            pdoaRaw = dwt_readpdoa();
            pdoaValid = (qRet >= 0); // garbage unless the STS CIR locked
        }

        RxSuccessEvent ev{
            .rawStatusRegister = st,
            .frameLength = len,
            .rxTimestampDtu = readRxTimestampDtu(),
            .stsQualityIndex = stsQuality,
            // Only CPERR (STS counter/quality failure) disqualifies a frame. RXFCE is set
            // by the driver on every SP3 no-data reception as its "no payload" marker and
            // must not be treated as an error here.
            .stsPassed = (qRet >= 0 && (st & DWT_INT_CPERR_BIT_MASK) == 0),
            .pdoaRaw = pdoaRaw,
            .pdoaValid = pdoaValid
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

core::Result<void> DW3000Controller::loadStsKeyIv(std::span<const std::byte, 16> key, std::span<const std::byte, 16> iv) {
    // STS_KEY0..3 + STS_IV0..3 are one contiguous 32-byte register block (0x2000C..0x2002C):
    // a single SPI write replaces the 8 per-word register writes the two separate loader
    // functions perform (each word = one transaction). The LOAD_IV strobe (STS_CTRL at
    // 0x20004, not adjacent) stays a second tiny transaction.
    const bool keyChanged = !(s_stsKeyValid && std::equal(key.begin(), key.end(), s_lastStsKey.begin()));

    std::array<uint8_t, 32> blob{};
    // Whole-16-byte reverse per word-group, matching packStsRegister's byte order
    for (size_t i = 0; i < 16; ++i) {
        blob[i] = static_cast<uint8_t>(key[15 - i]);
        blob[16 + i] = static_cast<uint8_t>(iv[15 - i]);
    }
    dwt_writetodevice(STS_KEY0_ID, 0U, static_cast<uint16_t>(blob.size()), blob.data());

    if (keyChanged) {
        std::memcpy(s_lastStsKey.data(), key.data(), 16);
        s_stsKeyValid = true;
    }
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
    // Same contiguous-register trick as startDelayedRx: a single DX_TIME write replaces
    // dwt_setdelayedtrxtime's transaction (the DREF_TIME/RX_FWTO words written alongside
    // are harmless for TX).
    std::array<uint8_t, 12> delayRegs{};
    const uint32_t dxTime = txStartTimeDtu & 0xFFFFFFFEUL;
    std::memcpy(&delayRegs[0], &dxTime, 4);
    dwt_writetodevice(DX_TIME_ID, 0U, static_cast<uint16_t>(delayRegs.size()), delayRegs.data());
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

    // DX_TIME (0x2C) + DREF_TIME (0x30, unused/zero) + RX_FWTO (0x34) form one contiguous
    // 12-byte block — a single SPI write replaces dwt_setdelayedtrxtime +
    // dwt_setrxtimeout (2 transactions). The DWT_START_RX_DELAYED command below latches
    // DX_TIME; SYS_CFG.RXWTOE is enabled permanently in configurePhy.
    std::array<uint8_t, 12> delayRegs{};
    const uint32_t dxTime = rxStartTimeDtu & 0xFFFFFFFEUL; // DX_TIME bit0 is reserved
    std::memcpy(&delayRegs[0], &dxTime, 4);
    // DREF_TIME stays zero
    std::memcpy(&delayRegs[8], &timeoutDtu, 2); // RX_FWTO (upper 2 bytes stay 0)
    dwt_writetodevice(DX_TIME_ID, 0U, static_cast<uint16_t>(delayRegs.size()), delayRegs.data());

    if (dwt_rxenable(DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR) != DWT_SUCCESS) {
        return std::unexpected(core::StatusCode::LateTransmission);
    }
    return {};
}

core::Result<void> DW3000Controller::startImmediateRx(uint16_t timeoutDtu) {
    // RXWTOE is permanently enabled (configurePhy), so the RX_FWTO value alone controls
    // the frame-wait behavior. The driver's own timeout-disabled path *clears RXWTOE*
    // rather than writing FWTO=0 — the hardware does not treat a zero count as disabled
    // (it fires immediately), so "wait indefinitely" must be represented by a maximal
    // window instead: 0xFFFF ≈ 67 s, far beyond any listen interval we use, and every
    // ranged arm overwrites it with the real window via the merged delay write.
    const uint32_t fwto = (timeoutDtu > 0) ? timeoutDtu : 0xFFFFU;
    std::array<uint8_t, 4> fwtoRegs{};
    std::memcpy(fwtoRegs.data(), &fwto, 4);
    dwt_writetodevice(RX_FWTO_ID, 0U, 4U, fwtoRegs.data());

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

DW3000Controller::FirstPathDiagnostics DW3000Controller::readFinalFirstPathDiagnostics() {
#ifdef CONFIG_UWB_NLOS_ENABLE
    // The distance comes from the Final frame's STS timestamp, so the relevant
    // CIR is the STS0 accumulator. dwt_nlos_alldiag is five small register
    // reads — far cheaper than dwt_readdiagnostics_acc's 216-byte burst, and
    // it returns exactly the fields the two power calculations need. It reads
    // raw diagnostics only; we ignore its own "result" heuristic and classify
    // ourselves from the power ratio.
    dwt_nlos_alldiag_t diag{};
    diag.diag_type = STS1;
    if (dwt_nlos_alldiag(&diag) != DWT_SUCCESS || diag.accumCount == 0) {
        return {};
    }

    const dwt_acc_idx_e acc = DWT_ACC_IDX_STS0_M;
    const dwt_cirdiags_t cirDiag{
        .power = diag.cir_power,
        .F1 = diag.F1,
        .F2 = diag.F2,
        .F3 = diag.F3,
        .peakAmp = 0,
        .peakIndex = 0,
        .FpIndex = 0,
        .accumCount = static_cast<uint16_t>(diag.accumCount)
    };

    int16_t fpPower = 0;
    int16_t rssi = 0;
    if (dwt_calculate_first_path_power(&cirDiag, acc, &fpPower) != DWT_SUCCESS ||
        dwt_calculate_rssi(&cirDiag, acc, &rssi) != DWT_SUCCESS) {
        return {};
    }
    return FirstPathDiagnostics{.firstPathPowerDbQ8 = fpPower, .rssiDbQ8 = rssi, .valid = true};
#else
    return {};
#endif
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
} // namespace uwb::transceiver