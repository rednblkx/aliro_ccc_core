#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"
#include "uwb/crypto/CccKeyDerivationEngine.hpp"
#include "uwb/crypto/Sp0SecurityEngine.hpp"
#include "uwb/hal/IClock.hpp"
#include "uwb/hal/ILogger.hpp"
#include "uwb/protocol/FrameCodec.hpp"
#include "uwb/protocol/SetupMessageCodec.hpp"
#include "uwb/ranging/AoAEstimator.hpp"
#include "uwb/ranging/DistanceEstimator.hpp"
#include "uwb/ranging/NlosDetector.hpp"
#include "uwb/ranging/RangeConsensusFilter.hpp"
#include "uwb/transceiver/DW3000Controller.hpp"

namespace uwb::session {

enum class SessionState {
    Uninitialized,
    Idle,
    PrePollListening,
    AwaitingPoll,
    TransmittingResponse,
    AwaitingFinal,
    AwaitingFinalData,
    Suspended
};

[[nodiscard]] constexpr std::string_view sessionStateToString(SessionState state) noexcept {
    switch (state) {
        case SessionState::Uninitialized:        return "Uninitialized";
        case SessionState::Idle:                 return "Idle";
        case SessionState::PrePollListening:     return "PrePollListening";
        case SessionState::AwaitingPoll:         return "AwaitingPoll";
        case SessionState::TransmittingResponse: return "TransmittingResponse";
        case SessionState::AwaitingFinal:        return "AwaitingFinal";
        case SessionState::AwaitingFinalData:    return "AwaitingFinalData";
        case SessionState::Suspended:            return "Suspended";
    }
    return "Unknown";
}

struct RangingResult {
    core::SessionId sessionId{0};
    core::BlockIndex blockIndex{0};
    // 0 for the first active round of the block, 1 for the second (two-round
    // MAC Mode only — lets the consumer compare the pair for front/behind).
    uint8_t roundInBlock{0};
    core::DistanceMm distance{0};
    ranging::RangeIntegrityReport integrity{};
    uint64_t timestampUs{0};
    // Angle of Arrival (optional, dual-antenna parts only): 1/100 deg, from the
    // DW3220's hardware PDoA on the Final frame's STS segments. Unambiguous range is
    // channel/spacing dependent (±54.6 deg on ch9 with 23 mm spacing); beyond it the
    // estimate has folded. Sign convention follows the DW3220 PDoA register.
    int32_t aoaCentiDegrees{0};
    bool aoaValid{false};
};

struct SessionNodeConfig {
    uint8_t responderIndex{0}; // 0 = Primary anchor (Lock), 1 = Secondary (Satellite)
    int8_t blockParityFilter{-1}; // -1 = Respond every block, 0 = Even blocks, 1 = Odd blocks
    core::DistanceMm antennaDelayBias{0};
    // AoA (optional): requires a DW3220-class dual-RX part with both antennas connected.
    // aoaAntennaSpacingMm is the antenna center-to-center spacing in mm (float, e.g. 23.1);
    // <= 0 disables the angle math even when PDoA mode is active.
    bool enableAoA{false};
    float aoaAntennaSpacingMm{0.0f};
};

using RangeCallback = std::function<void(const RangingResult&)>;

class RangingSession final : public transceiver::ITransceiverListener {
public:
    RangingSession(
        transceiver::DW3000Controller& transceiver,
        crypto::CccKeyDerivationEngine& kdf,
        crypto::Sp0SecurityEngine& sp0,
        ranging::RangeConsensusFilter& filter,
        hal::IClock& clock,
        hal::ILogger* logger = nullptr) noexcept;

    ~RangingSession() override;

    [[nodiscard]] core::Result<void> start(
        std::span<const std::byte, 32> ursk,
        const protocol::setup::RangingSessionParameters& params,
        SessionNodeConfig nodeConfig,
        RangeCallback callback);

    core::Result<void> stop();
    core::Result<void> suspend();
    core::Result<void> resume();

    core::Result<void> resumeWithAnchor(core::StsIndex newStsIndex0, uint64_t newTime0Us);

    [[nodiscard]] SessionState getState() const noexcept { return m_state; }
    [[nodiscard]] core::SessionId getSessionId() const noexcept { return m_params.sessionId; }

    // ITransceiverListener Interface
    void onRxSuccess(const transceiver::RxSuccessEvent& event) override;
    void onRxTimeout() override;
    void onRxError(uint32_t errorStatus) override;
    void onTxComplete() override;

private:
    transceiver::DW3000Controller& m_transceiver;
    crypto::CccKeyDerivationEngine& m_kdf;
    crypto::Sp0SecurityEngine& m_sp0;
    ranging::RangeConsensusFilter& m_filter;
    hal::IClock& m_clock;
    hal::ILogger* m_logger;

    SessionState m_state{SessionState::Uninitialized};
    SessionNodeConfig m_nodeConfig{};
    protocol::setup::RangingSessionParameters m_params{};
    RangeCallback m_callback;

    // Master Cryptographic Material
    std::array<std::byte, 32> m_ursk{};
    std::array<std::byte, 32> m_mursk{};
    std::array<std::byte, 32> m_mupsk2{};
    std::array<std::byte, 16> m_mupsk1{};
    std::array<std::byte, 16> m_saltedHash{};
    core::MacAddresses m_addresses{};
    bool m_materialValid{false};
    core::StatusCode m_lastDeriveError{core::StatusCode::InvalidParameter};

    // Slot-Specific State & Timestamps
    core::BlockIndex m_currentBlock{0};
    core::SlotIndex m_currentRound{0};
    core::StsIndex m_armedPollStsIndex{0};
    uint64_t m_pollRxTimestampDtu{0};
    uint64_t m_respTxTimestampDtu{0};
    uint64_t m_finalRxTimestampDtu{0};
    int16_t m_finalStsQuality{0};
    bool m_finalStsPassed{false};
    int16_t m_finalPdoaRaw{0};
    bool m_finalPdoaValid{false};
    // First-path-power NLOS inputs sampled off the Final frame's STS diagnostics
    // (read after the FinalData arm — outside the arm deadline). Q8.8 dBm.
    int16_t m_finalFirstPathDbQ8{0};
    int16_t m_finalRssiDbQ8{0};
    bool m_finalNlosDiagValid{false};

    // Pre-warmed slot keys: all SP3 legs of a block (Poll/Response/Final) are derivable
    // during the block idle — dURSK is round-constant and the Poll STS index follows the
    // STS schedule (fixed stride within a round position) — so the PrePoll handler only
    // performs fast register writes before arming, and no KDF ever runs on the
    // Poll->Response->Final critical path.
    struct CycleKeys {
        core::StsIndex pollStsIndex{0};
        crypto::CccKeyDerivationEngine::SlotCryptoMaterial poll{};
        crypto::CccKeyDerivationEngine::SlotCryptoMaterial response{};
        crypto::CccKeyDerivationEngine::SlotCryptoMaterial final_{};
    };
    bool m_warmValid{false};
    CycleKeys m_warm{};
    // Materials for the currently armed cycle (copied from warm, or derived inline in bootstrap)
    bool m_armedKeysValid{false};
    CycleKeys m_armed{};

    core::FrameCounter m_lastPrePollCounter{0};
    core::FrameCounter m_lastFinalDataCounter{0};
    bool m_hasReceivedPrePollCounter{false};
    bool m_hasReceivedFinalDataCounter{false};
    core::StsIndex m_lastPrePollStsIndex{0};
    bool m_hasPrePollStsIndex{false};

    std::array<std::byte, 256> m_rxFrameBuffer{};

    // Stashed PrePoll frame: decoded only after the Response TX is armed so the
    // decrypt+KDF never blocks the PrePoll->Poll arm nor the Poll->Response arm.
    std::array<std::byte, 128> m_stashFrame{};
    uint16_t m_stashLen{0};

    void transitionTo(SessionState newState) noexcept;
    void armPrePollListening();
    void processStashedPrePoll();
    // Derives m_mupsk1/2, m_mursk, m_saltedHash, m_addresses from m_ursk + m_params.
    // Sets m_materialValid (false on failure, error code in m_lastDeriveError).
    void deriveSessionMaterial();

    // STS-index advance between consecutive blocks' Poll slots (all slots in a block
    // count, including unused ones): roundsPerBlock * slotsPerRound.
    [[nodiscard]] uint32_t blockStsStride() const noexcept;
    // Derive slot keys for the whole next cycle (Poll/Response/Final) into m_warm
    void refreshWarmKeys(core::StsIndex acceptedPollStsIndex);
    // Derive slot keys for the cycle anchored at pollStsIndex (bootstrap path)
    [[nodiscard]] core::Result<void> deriveCycleKeys(core::StsIndex pollStsIndex, CycleKeys& out) const noexcept;

    void handlePrePollReception(const transceiver::RxSuccessEvent& event);
    // Validate/decode a stashed PrePoll frame; returns the payload when it is a genuine
    // PrePoll for this session (fresh counter, matching addresses, decrypt OK).
    [[nodiscard]] core::Result<protocol::PrePollPayload> decodePrePollFrame(
        std::span<const std::byte> frame, const transceiver::RxSuccessEvent& event);
    void handlePollReception(const transceiver::RxSuccessEvent& event);
    void handleFinalReception(const transceiver::RxSuccessEvent& event);
    void handleFinalDataReception(const transceiver::RxSuccessEvent& event);

    [[nodiscard]] bool isBlockParityEligible(core::BlockIndex block) const noexcept;

    [[nodiscard]] uint32_t roundsPerBlock() const noexcept;
    // Absolute STS index of the Poll slot of (block, round). Returns 0 when the
    // schedule can't be computed (invalid params).
    [[nodiscard]] core::StsIndex pollStsIndexFor(core::BlockIndex block,
                                                 core::SlotIndex round) const noexcept;
    [[nodiscard]] core::SlotIndex scheduledRoundFor(core::BlockIndex block) const noexcept;
    // Warm-refresh target: the next exchange after the one at (block, round).
    // Returns false when the next exchange is not schedulable (adaptive hopping,
    // invalid schedule) — the caller then falls back to the bootstrap path.
    [[nodiscard]] bool nextScheduledExchange(core::BlockIndex block, core::SlotIndex round,
                                             core::BlockIndex& nextBlock,
                                             core::SlotIndex& nextRound) const noexcept;
};

} // namespace uwb::session
