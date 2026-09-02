#include "uwb/session/RangingSession.hpp"
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>

namespace uwb::session {

namespace {

// Per-round logging inside the ranging state machine is OFF by default: the handler runs
// inside the 1.84 ms PrePoll->Poll arm deadline and ESP log output is synchronous UART
// (~5 ms per line), which alone blows every arm deadline. Enable only for bench debugging.
#ifndef UWB_HOT_PATH_LOGS
#define UWB_HOT_PATH_LOGS 0
#endif

#if UWB_HOT_PATH_LOGS
#define HOT_LOG(level, fmt, ...)                                                     \
    do {                                                                             \
        if (m_logger) {                                                              \
            char b_[128];                                                            \
            std::snprintf(b_, sizeof(b_), fmt, ##__VA_ARGS__);                       \
            m_logger->log(level, "RangingSession", b_);                              \
        }                                                                            \
    } while (0)
#else
#define HOT_LOG(level, fmt, ...) do {} while (0)
#endif

// In DW3000 high-32 ticks (4.0064 ns units):
// 1 RSTU = 833.333 ns -> 833.333 / 4.0064 = 208 high-32 ticks per RSTU
constexpr uint32_t TicksPerRstuHi32 = 208U;

// Lead window: open RX ~160 us before expected preamble arrival
constexpr uint32_t LeadTimeHi32 = 40000U;

// RX search window timeout in driver units (1.0256 us each) — ~1.4 ms
constexpr uint16_t WindowTimeoutDtu = 1350;

// Reply-path excess pre-subtracted from the Response RMARKER to keep
// single-sided range unbiased
constexpr uint32_t RespAntDelayHi32 = 62U;

bool matchKeySource(const std::array<std::byte, 4>& a, const std::array<std::byte, 4>& b) noexcept {
    const bool direct = (a == b);
    const bool reversed = (a[0] == b[3] && a[1] == b[2] && a[2] == b[1] && a[3] == b[0]);
    return direct || reversed;
}

bool matchShortAddress(uint16_t a, uint16_t b) noexcept {
    const uint16_t swapped = static_cast<uint16_t>((b >> 8) | (b << 8));
    return (a == b) || (a == swapped);
}

} // namespace

RangingSession::RangingSession(
    transceiver::DW3000Controller& transceiver,
    crypto::CccKeyDerivationEngine& kdf,
    crypto::Sp0SecurityEngine& sp0,
    ranging::RangeConsensusFilter& filter,
    hal::IClock& clock,
    hal::ILogger* logger) noexcept
    : m_transceiver(transceiver),
      m_kdf(kdf),
      m_sp0(sp0),
      m_filter(filter),
      m_clock(clock),
      m_logger(logger) {
}

RangingSession::~RangingSession() {
    (void)stop();
}

void RangingSession::transitionTo(SessionState newState) noexcept {
    HOT_LOG(hal::LogLevel::Debug, "State: %s -> %s",
            sessionStateToString(m_state).data(), sessionStateToString(newState).data());
    m_state = newState;
}

core::Result<void> RangingSession::start(
        std::span<const std::byte, 32> ursk,
        const protocol::setup::RangingSessionParameters& params,
        SessionNodeConfig nodeConfig,
        RangeCallback callback) {
    m_transceiver.forceReceiverOff();
    m_params = params;
    m_nodeConfig = nodeConfig;
    m_callback = std::move(callback);
    std::memcpy(m_ursk.data(), ursk.data(), 32);

    if (m_logger) {
        char buf[160];
        std::snprintf(buf, sizeof(buf), "Starting session 0x%08" PRIX32 " (ch=%d, sync=%d, slot=%u rstu, blk=%" PRIu32 " ms, sts0=0x%08" PRIX32 ")",
                      params.sessionId.get(),
                      static_cast<int>(params.channel),
                      static_cast<int>(params.syncCodeIndex),
                      static_cast<unsigned int>(params.slotDurationRstu),
                      params.durationMs,
                      params.stsIndex0.get());
        m_logger->log(hal::LogLevel::Info, "RangingSession", buf);
    }

    auto mupsk1Res = m_kdf.deriveMupsk1(m_ursk);
    if (!mupsk1Res) return std::unexpected(mupsk1Res.error());
    m_mupsk1 = *mupsk1Res;

    auto mupsk2Res = m_kdf.deriveMupsk2(m_ursk);
    if (!mupsk2Res) return std::unexpected(mupsk2Res.error());
    m_mupsk2 = *mupsk2Res;

    auto murskRes = m_kdf.deriveMursk(m_ursk);
    if (!murskRes) return std::unexpected(murskRes.error());
    m_mursk = *murskRes;

    std::array<std::byte, 17> rcfg{};
    rcfg[0] = std::byte{0x01};
    rcfg[1] = std::byte{0x00};
    rcfg[2] = static_cast<std::byte>((m_params.uwbConfigId >> 8) & 0xFF);
    rcfg[3] = static_cast<std::byte>(m_params.uwbConfigId & 0xFF);
    rcfg[4] = static_cast<std::byte>((m_params.sessionId.get() >> 24) & 0xFF);
    rcfg[5] = static_cast<std::byte>((m_params.sessionId.get() >> 16) & 0xFF);
    rcfg[6] = static_cast<std::byte>((m_params.sessionId.get() >> 8) & 0xFF);
    rcfg[7] = static_cast<std::byte>(m_params.sessionId.get() & 0xFF);
    rcfg[8] = static_cast<std::byte>((m_params.stsIndex0.get() >> 24) & 0xFF);
    rcfg[9] = static_cast<std::byte>((m_params.stsIndex0.get() >> 16) & 0xFF);
    rcfg[10] = static_cast<std::byte>((m_params.stsIndex0.get() >> 8) & 0xFF);
    rcfg[11] = static_cast<std::byte>(m_params.stsIndex0.get() & 0xFF);
    rcfg[12] = static_cast<std::byte>(m_params.responderCount);
    rcfg[13] = static_cast<std::byte>(m_params.durationMs / 96);
    rcfg[14] = static_cast<std::byte>(m_params.slotsPerRound);
    rcfg[15] = static_cast<std::byte>(m_params.slotDurationRstu / 400);
    rcfg[16] = static_cast<std::byte>(m_params.pulseShapeCombo);

    auto saltedHashRes = m_kdf.deriveSaltedHash(m_ursk, rcfg);
    if (!saltedHashRes) return std::unexpected(saltedHashRes.error());
    m_saltedHash = *saltedHashRes;

    auto addrRes = m_kdf.deriveAddresses(m_mupsk2, m_params.stsIndex0);
    if (!addrRes) return std::unexpected(addrRes.error());
    m_addresses = *addrRes;

    if (m_logger) {
        char buf[160];
        std::snprintf(buf, sizeof(buf), "Derived UAD: dest=0x%04" PRIX16 ", ks=%02x%02x%02x%02x, srcLong=%02x%02x%02x%02x%02x%02x%02x%02x",
                      m_addresses.destinationShort,
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.keySource[0])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.keySource[1])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.keySource[2])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.keySource[3])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[0])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[1])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[2])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[3])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[4])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[5])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[6])),
                      static_cast<unsigned int>(static_cast<uint8_t>(m_addresses.sourceLong[7])));
        m_logger->log(hal::LogLevel::Info, "RangingSession", buf);
    }

    m_filter.reset();
    m_hasReceivedPrePollCounter = false;
    m_hasReceivedFinalDataCounter = false;
    m_hasPrePollStsIndex = false;
    m_lastPrePollStsIndex = core::StsIndex{0};
    m_warmValid = false;
    m_armedKeysValid = false;

    const uint8_t syncCode = (m_params.syncCodeIndex >= 9 && m_params.syncCodeIndex <= 12)
                                 ? m_params.syncCodeIndex
                                 : static_cast<uint8_t>(9);

    transceiver::TransceiverConfig hwCfg{
        .channel = m_params.channel,
        .preambleLengthSymbols = 64,
        .syncCode = syncCode,
        .sfd = core::SfdType::Ieee4a,
        .sfdTimeoutSymbols = 65,
        .rxPacSize = 8,
        .antennaDelay = 0
    };

    auto cfgRes = m_transceiver.configurePhy(hwCfg);
    if (!cfgRes) {
        if (m_logger) m_logger->log(hal::LogLevel::Error, "RangingSession", "configurePhy failed");
        return std::unexpected(cfgRes.error());
    }

    m_transceiver.setListener(this);
    armPrePollListening();

    return {};
}

core::Result<void> RangingSession::stop() {
    m_transceiver.setListener(nullptr);
    m_transceiver.forceReceiverOff();
    transitionTo(SessionState::Idle);
    return {};
}

core::Result<void> RangingSession::suspend() {
    m_transceiver.forceReceiverOff();
    transitionTo(SessionState::Suspended);
    return {};
}

core::Result<void> RangingSession::resume() {
    if (m_state != SessionState::Suspended) {
        return std::unexpected(core::StatusCode::InvalidState);
    }
    armPrePollListening();
    return {};
}

bool RangingSession::isBlockParityEligible(core::BlockIndex block) const noexcept {
    if (m_nodeConfig.blockParityFilter < 0) {
        return true;
    }
    return (static_cast<int32_t>(block.get()) & 1) == m_nodeConfig.blockParityFilter;
}

void RangingSession::armPrePollListening() {
    m_transceiver.forceReceiverOff();
    (void)m_transceiver.configureStsMode(transceiver::StsMode::Off);
    auto rxRes = m_transceiver.startImmediateRx(0);
    if (!rxRes && m_logger) {
        m_logger->log(hal::LogLevel::Warn, "RangingSession", "[Pre-POLL ARM] startImmediateRx failed");
    }
    transitionTo(SessionState::PrePollListening);
    processStashedPrePoll();
}

void RangingSession::processStashedPrePoll() {
    if (m_stashLen == 0) {
        return;
    }
    const std::span<const std::byte> frame(m_stashFrame.data(), m_stashLen);
    m_stashLen = 0;

    if (auto prePoll = decodePrePollFrame(frame, transceiver::RxSuccessEvent{})) {
        m_currentBlock = prePoll->rangingBlock;
        if (isBlockParityEligible(m_currentBlock)) {
            refreshWarmKeys(prePoll->pollStsIndex);
        }
    } else {
        m_warmValid = false; // stale/garbage: force bootstrap on the next block
    }
}

void RangingSession::onRxSuccess(const transceiver::RxSuccessEvent& event) {
    switch (m_state) {
        case SessionState::PrePollListening:
            handlePrePollReception(event);
            break;
        case SessionState::AwaitingPoll:
            handlePollReception(event);
            break;
        case SessionState::AwaitingFinal:
            handleFinalReception(event);
            break;
        case SessionState::AwaitingFinalData:
            handleFinalDataReception(event);
            break;
        default:
            break;
    }
}

void RangingSession::onRxTimeout() {
    if (m_state == SessionState::Idle || m_state == SessionState::Uninitialized ||
        m_state == SessionState::Suspended) {
        return;
    }
    if (m_state == SessionState::PrePollListening) {
        (void)m_transceiver.startImmediateRx(0);
        return;
    }
    if (m_logger) {
        char buf[80];
        std::snprintf(buf, sizeof(buf), "[RX TO] Timeout in state %s",
                      sessionStateToString(m_state).data());
        m_logger->log(hal::LogLevel::Warn, "RangingSession", buf);
    }
    armPrePollListening();
}

void RangingSession::onRxError(uint32_t errorStatus) {
    if (m_state == SessionState::Idle || m_state == SessionState::Uninitialized ||
        m_state == SessionState::Suspended) {
        return;
    }
    if (m_logger) {
        char buf[80];
        std::snprintf(buf, sizeof(buf), "[RX ERR] Status=0x%08" PRIX32 " in %s",
                      errorStatus, sessionStateToString(m_state).data());
        m_logger->log(hal::LogLevel::Warn, "RangingSession", buf);
    }
    armPrePollListening();
}

void RangingSession::onTxComplete() {
    if (m_state == SessionState::TransmittingResponse) {
        m_respTxTimestampDtu = m_transceiver.readTxTimestampDtu();

        if (!m_armedKeysValid) {
            armPrePollListening();
            return;
        }
        const uint32_t finalSlotOffset = 1U + static_cast<uint32_t>(m_params.responderCount);
        (void)m_transceiver.loadStsKey(m_armed.final_.durskKey);
        (void)m_transceiver.configureStsMode(transceiver::StsMode::NoDataSp3);
        (void)m_transceiver.loadStsIv(m_armed.final_.stsIv);

        const uint32_t slotTicksHi32 = static_cast<uint32_t>(m_params.slotDurationRstu) * TicksPerRstuHi32;
        const uint32_t pollHi32 = static_cast<uint32_t>(m_pollRxTimestampDtu >> 8);
        const uint32_t finalRxTime = pollHi32 + (finalSlotOffset * slotTicksHi32) - LeadTimeHi32;

        if (!m_transceiver.startDelayedRx(finalRxTime, WindowTimeoutDtu)) {
            (void)m_transceiver.startImmediateRx(WindowTimeoutDtu);
        }
        transitionTo(SessionState::AwaitingFinal);
        return;
    }
}

void RangingSession::handlePrePollReception(const transceiver::RxSuccessEvent& event) {
    auto readLen = m_transceiver.readReceivedData(m_rxFrameBuffer);
    if (!readLen || *readLen < protocol::MacHeaderLength) {
        armPrePollListening();
        return;
    }
    const std::span<const std::byte> frame(m_rxFrameBuffer.data(), *readLen);

    const uint32_t slotTicksHi32 = static_cast<uint32_t>(m_params.slotDurationRstu) * TicksPerRstuHi32;
    const uint32_t prePollRxHi32 = static_cast<uint32_t>(event.rxTimestampDtu >> 8);
    const uint32_t pollRxTime = prePollRxHi32 + slotTicksHi32 - LeadTimeHi32;

    if (m_warmValid) {
        auto mhr = protocol::FrameCodec::decodeHeader(frame);
        if (!mhr || mhr->messageId != protocol::MessageIdentifier::PrePoll ||
            !matchShortAddress(mhr->destinationShortAddress, m_addresses.destinationShort) ||
            !matchKeySource(mhr->keySource, m_addresses.keySource) ||
            (m_hasReceivedPrePollCounter && mhr->frameCounter.get() <= m_lastPrePollCounter.get())) {
            armPrePollListening();
            return;
        }

        m_armed = m_warm;
        m_armedKeysValid = true;
        m_armedPollStsIndex = m_armed.pollStsIndex;
        (void)m_transceiver.loadStsKey(m_armed.poll.durskKey);
        (void)m_transceiver.configureStsMode(transceiver::StsMode::NoDataSp3);
        (void)m_transceiver.loadStsIv(m_armed.poll.stsIv);

        m_stashLen = static_cast<uint16_t>(std::min<size_t>(frame.size(), m_stashFrame.size()));
        std::memcpy(m_stashFrame.data(), frame.data(), m_stashLen);

        constexpr uint16_t ImmediateSearchWindowDtu = 4000;
        if (m_transceiver.startDelayedRx(pollRxTime, WindowTimeoutDtu)) {
            transitionTo(SessionState::AwaitingPoll);
        } else {
            (void)m_transceiver.startImmediateRx(ImmediateSearchWindowDtu);
            transitionTo(SessionState::AwaitingPoll);
        }
        return;
    }

    auto prePollRes = decodePrePollFrame(frame, event);
    if (!prePollRes) {
        armPrePollListening();
        return;
    }
    m_currentBlock = prePollRes->rangingBlock;
    if (!isBlockParityEligible(m_currentBlock)) {
        armPrePollListening();
        return;
    }

    m_transceiver.forceReceiverOff();
    auto cycleRes = deriveCycleKeys(prePollRes->pollStsIndex, m_armed);
    if (!cycleRes) {
        armPrePollListening();
        return;
    }
    m_armedKeysValid = true;
    m_armedPollStsIndex = m_armed.pollStsIndex;

    HOT_LOG(hal::LogLevel::Debug, "[ARM] Poll STS idx=%" PRIu32 " (bootstrap)",
            m_armedPollStsIndex.get());

    (void)m_transceiver.loadStsKey(m_armed.poll.durskKey);
    (void)m_transceiver.configureStsMode(transceiver::StsMode::NoDataSp3);
    (void)m_transceiver.loadStsIv(m_armed.poll.stsIv);

    constexpr uint16_t ImmediateSearchWindowDtu = 4000;
    if (m_transceiver.startDelayedRx(pollRxTime, WindowTimeoutDtu)) {
        transitionTo(SessionState::AwaitingPoll);
    } else {
        (void)m_transceiver.startImmediateRx(ImmediateSearchWindowDtu);
        transitionTo(SessionState::AwaitingPoll);
    }

    refreshWarmKeys(prePollRes->pollStsIndex);
}

core::Result<protocol::PrePollPayload> RangingSession::decodePrePollFrame(
        std::span<const std::byte> frame, const transceiver::RxSuccessEvent& event) {
    (void)event;
    auto mhr = protocol::FrameCodec::decodeHeader(frame);
    if (!mhr || mhr->messageId != protocol::MessageIdentifier::PrePoll) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    if (!matchShortAddress(mhr->destinationShortAddress, m_addresses.destinationShort) ||
        !matchKeySource(mhr->keySource, m_addresses.keySource)) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    if (m_hasReceivedPrePollCounter && mhr->frameCounter.get() <= m_lastPrePollCounter.get()) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const size_t securedLen =
        static_cast<size_t>(mhr->payloadLength) + crypto::Sp0SecurityEngine::MicLength;
    if (frame.size() < protocol::MacHeaderLength + securedLen) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    std::array<std::byte, protocol::PrePollPayloadLength> decryptedPayload{};
    auto decRes = m_sp0.decryptPayload(
        m_mupsk1,
        m_addresses.sourceLong,
        mhr->frameCounter,
        frame.subspan(0, protocol::MacHeaderLength),
        frame.subspan(protocol::MacHeaderLength, securedLen),
        decryptedPayload
    );
    if (!decRes) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    auto prePoll = protocol::FrameCodec::decodePrePoll(decryptedPayload);
    if (!prePoll || prePoll->sessionId != m_params.sessionId) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    if (m_hasPrePollStsIndex &&
        static_cast<int32_t>(prePoll->pollStsIndex.get() - m_lastPrePollStsIndex.get()) <= 0) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    m_lastPrePollStsIndex = prePoll->pollStsIndex;
    m_hasPrePollStsIndex = true;
    m_lastPrePollCounter = mhr->frameCounter;
    m_hasReceivedPrePollCounter = true;
    return prePoll;
}

void RangingSession::refreshWarmKeys(core::StsIndex acceptedPollStsIndex) {
    const uint32_t stride = blockStsStride();
    if (stride == 0) {
        m_warmValid = false;
        return;
    }
    if (deriveCycleKeys(core::StsIndex{acceptedPollStsIndex.get() + stride}, m_warm)) {
        m_warmValid = true;
        HOT_LOG(hal::LogLevel::Debug, "[WARM] next Poll STS idx=%" PRIu32,
                m_warm.pollStsIndex.get());
    } else {
        m_warmValid = false;
    }
}

core::Result<void> RangingSession::deriveCycleKeys(core::StsIndex pollStsIndex, CycleKeys& out) const noexcept {
    const uint32_t n = static_cast<uint32_t>(m_params.responderCount);
    out.pollStsIndex = pollStsIndex;

    auto pollKeys = m_kdf.deriveSlotKeys(m_mursk, m_saltedHash, pollStsIndex,
                                         m_params.slotsPerRound, m_params.stsIndex0);
    if (!pollKeys) return std::unexpected(pollKeys.error());
    out.poll = *pollKeys;

    auto respKeys = m_kdf.deriveSlotKeys(
        m_mursk, m_saltedHash,
        core::StsIndex{pollStsIndex.get() + 1U + static_cast<uint32_t>(m_nodeConfig.responderIndex)},
        m_params.slotsPerRound, m_params.stsIndex0);
    if (!respKeys) return std::unexpected(respKeys.error());
    out.response = *respKeys;

    auto finalKeys = m_kdf.deriveSlotKeys(
        m_mursk, m_saltedHash,
        core::StsIndex{pollStsIndex.get() + 1U + n},
        m_params.slotsPerRound, m_params.stsIndex0);
    if (!finalKeys) return std::unexpected(finalKeys.error());
    out.final_ = *finalKeys;

    return {};
}

uint32_t RangingSession::blockStsStride() const noexcept {
    if (m_params.slotDurationRstu == 0 || m_params.slotsPerRound == 0 || m_params.durationMs == 0) {
        return 0;
    }
    // 1 RSTU = 416/499.2 MHz = 833.33 ns = 5/6 µs -> slot = RSTU * 5/6 µs
    const uint64_t roundDurationUs =
        static_cast<uint64_t>(m_params.slotsPerRound) *
        static_cast<uint64_t>(m_params.slotDurationRstu) * 5ULL / 6ULL;
    if (roundDurationUs == 0) {
        return 0;
    }
    // rounds per block = durationMs / round duration; every slot of the block advances
    // the STS index, including unused ones
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(m_params.durationMs) * 1000ULL) / roundDurationUs) *
        m_params.slotsPerRound;
}

void RangingSession::handlePollReception(const transceiver::RxSuccessEvent& event) {
    HOT_LOG(hal::LogLevel::Info, "[POLL RX] stsPassed=%d, qual=%d",
            event.stsPassed ? 1 : 0, static_cast<int>(event.stsQualityIndex));

    if (!event.stsPassed) {
        armPrePollListening();
        return;
    }

    m_pollRxTimestampDtu = event.rxTimestampDtu;

    // Schedule Response: Poll Rx + (1 + responderIndex) * slotTicks - reply-path excess
    const uint32_t slotTicksHi32 = static_cast<uint32_t>(m_params.slotDurationRstu) * TicksPerRstuHi32;
    const uint32_t pollHi32 = static_cast<uint32_t>(m_pollRxTimestampDtu >> 8);
    const uint32_t slotOffset = 1U + static_cast<uint32_t>(m_nodeConfig.responderIndex);
    const uint32_t respTxTime = pollHi32 + (slotOffset * slotTicksHi32) - RespAntDelayHi32;

    if (!m_armedKeysValid) {
        armPrePollListening();
        return;
    }
    (void)m_transceiver.loadStsKey(m_armed.response.durskKey);
    (void)m_transceiver.loadStsIv(m_armed.response.stsIv);
    (void)m_transceiver.configureStsMode(transceiver::StsMode::NoDataSp3);

    // SP3 (No-Data STS) response — empty payload, ranging frame
    if (m_transceiver.startDelayedTx(respTxTime, {}, /*rangingFrame=*/true)) {
        transitionTo(SessionState::TransmittingResponse);
    } else {
        // Rate-limited probe: distinguishes a late
        // target (margin <= 0), a hardware HPDWARN warning (st bit 27), or a wedged
        // device state. margin unit: 250 ticks = 1 us.
        static uint32_t probeCount = 0;
        if (m_logger && (probeCount++ % 16u) == 0u) {
            const int32_t marginTicks =
                static_cast<int32_t>(respTxTime - m_transceiver.readSystemTimestampDtu());
            const uint32_t st = m_transceiver.readSysStatusLo();
            char buf[112];
            std::snprintf(buf, sizeof(buf),
                          "[RESP PROBE] margin=%ld us st=0x%08" PRIX32,
                          static_cast<long>(marginTicks / 250), st);
            m_logger->log(hal::LogLevel::Warn, "RangingSession", buf);
        }
        armPrePollListening();
    }
}

void RangingSession::handleFinalReception(const transceiver::RxSuccessEvent& event) {
    m_finalRxTimestampDtu = event.rxTimestampDtu;
    m_finalStsQuality = event.stsQualityIndex;
    m_finalStsPassed = event.stsPassed;

    HOT_LOG(hal::LogLevel::Info, "[FINAL RX] stsPassed=%d, qual=%d",
            event.stsPassed ? 1 : 0, static_cast<int>(event.stsQualityIndex));

    m_transceiver.forceReceiverOff();
    (void)m_transceiver.configureStsMode(transceiver::StsMode::Off);

    const uint32_t slotTicksHi32 = static_cast<uint32_t>(m_params.slotDurationRstu) * TicksPerRstuHi32;
    const uint32_t pollHi32 = static_cast<uint32_t>(m_pollRxTimestampDtu >> 8);
    const uint32_t finalDataOffset = 2U + static_cast<uint32_t>(m_params.responderCount);
    const uint32_t finalDataRxTime = pollHi32 + (finalDataOffset * slotTicksHi32) - LeadTimeHi32;

    if (!m_transceiver.startDelayedRx(finalDataRxTime, WindowTimeoutDtu * 2)) {
        (void)m_transceiver.startImmediateRx(WindowTimeoutDtu * 2);
    }
    transitionTo(SessionState::AwaitingFinalData);
    processStashedPrePoll();
}

void RangingSession::handleFinalDataReception(const transceiver::RxSuccessEvent& event) {
    (void)event;
    auto readLen = m_transceiver.readReceivedData(m_rxFrameBuffer);
    if (!readLen || *readLen < protocol::MacHeaderLength) {
        armPrePollListening();
        return;
    }

    std::span<const std::byte> frame(m_rxFrameBuffer.data(), *readLen);
    auto mhr = protocol::FrameCodec::decodeHeader(frame);
    if (!mhr || mhr->messageId != protocol::MessageIdentifier::FinalData) {
        armPrePollListening();
        return;
    }

    if (m_hasReceivedFinalDataCounter && mhr->frameCounter.get() <= m_lastFinalDataCounter.get()) {
        armPrePollListening();
        return;
    }

    const size_t securedLen =
        static_cast<size_t>(mhr->payloadLength) + crypto::Sp0SecurityEngine::MicLength;
    if (*readLen < protocol::MacHeaderLength + securedLen) {
        armPrePollListening();
        return;
    }

    auto slotKeys = m_kdf.deriveSlotKeys(m_mursk, m_saltedHash, m_armedPollStsIndex,
                                         m_params.slotsPerRound, m_params.stsIndex0);
    if (!slotKeys) {
        armPrePollListening();
        return;
    }

    std::array<std::byte, 128> decryptedPayload{};
    auto decRes = m_sp0.decryptPayload(
        slotKeys->dudskKey,
        m_addresses.sourceLong,
        mhr->frameCounter,
        frame.subspan(0, protocol::MacHeaderLength),
        frame.subspan(protocol::MacHeaderLength, securedLen),
        decryptedPayload
    );

    if (!decRes) {
        if (m_logger) m_logger->log(hal::LogLevel::Warn, "RangingSession", "[FINAL_DATA] Decrypt fail");
        armPrePollListening();
        return;
    }

    auto finalData = protocol::FrameCodec::decodeFinalData(std::span<const std::byte>(decryptedPayload.data(), *decRes));
    if (!finalData || finalData->sessionId != m_params.sessionId) {
        armPrePollListening();
        return;
    }

    m_lastFinalDataCounter = mhr->frameCounter;
    m_hasReceivedFinalDataCounter = true;

    const auto expectedFinalSts = core::StsIndex{
        m_armedPollStsIndex.get() + 1U + static_cast<uint32_t>(m_params.responderCount)};
    if (finalData->finalStsIndex != expectedFinalSts) {
        armPrePollListening();
        return;
    }

    const auto it = std::find_if(
        finalData->responderReports.begin(),
        finalData->responderReports.end(),
        [this](const protocol::ResponderTimestampReport& r) {
            return r.responderIndex == m_nodeConfig.responderIndex;
        }
    );

    if (it != finalData->responderReports.end()) {
        ranging::DoubleSidedTwrTimestamps dsTs{
            .round1Dtu = it->rxTimestampDtu,
            .reply1Dtu = static_cast<uint32_t>(m_respTxTimestampDtu - m_pollRxTimestampDtu),
            .round2Dtu = static_cast<uint32_t>(m_finalRxTimestampDtu - m_respTxTimestampDtu),
            .reply2Dtu = static_cast<uint32_t>(finalData->txTimestampFinalDtu - it->rxTimestampDtu)
        };

        auto distanceRes = ranging::DistanceEstimator::calculateDistance(dsTs, m_nodeConfig.antennaDelayBias);
        if (distanceRes) {
            auto integrity = m_filter.ingest(*distanceRes, m_finalStsPassed ? 0 : -1, m_finalStsQuality);

            if (m_logger) {
                char buf[128];
                std::snprintf(buf, sizeof(buf), ">>> [RANGE RESULT] blk=%" PRIu16 ", dist=%" PRId32 " cm, stsQuality=%d, trusted=%d",
                              m_currentBlock.get(),
                              distanceRes->get() / 10,
                              static_cast<int>(m_finalStsQuality),
                              integrity.isTrusted ? 1 : 0);
                m_logger->log(hal::LogLevel::Debug, "RangingSession", buf);
            }

            if (m_callback) {
                RangingResult result{
                    .sessionId = m_params.sessionId,
                    .blockIndex = m_currentBlock,
                    .distance = *distanceRes,
                    .integrity = integrity,
                    .timestampUs = m_clock.getMonotonicTimeUs()
                };
                m_callback(result);
            }
        }
    }

    armPrePollListening();
}

} // namespace uwb::session