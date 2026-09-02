#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"

namespace uwb::protocol::setup {

enum class ProtocolCategory : uint8_t {
    AccessProfile         = 0x00,
    UwbRangingService     = 0x01,
    Notification          = 0x02,
    SupplementaryService  = 0x03
};

enum class MessageType : uint8_t {
    RangingSetupM1      = 0x00,
    RangingSetupM2      = 0x01,
    RangingSetupM3      = 0x02,
    RangingSetupM4      = 0x03,
    SuspendRequest      = 0x04,
    SuspendResponse     = 0x05,
    ResumeRequest       = 0x06,
    ResumeResponse      = 0x07
};

enum class AttributeTag : uint8_t {
    ConfigId              = 0x00,
    PulseShapeCombo       = 0x01,
    SessionId             = 0x02,
    ChannelBitmask        = 0x03,
    RanMultiplier         = 0x04,
    SlotBitmask           = 0x05,
    SyncCodeIndexBitmask  = 0x06,
    SyncCodeIndex         = 0x07,
    HoppingConfigBitmask  = 0x08,
    ChapsPerSlot          = 0x09,
    NumResponders         = 0x0A,
    SlotsPerRound         = 0x0B,
    StsIndex0             = 0x0C,
    UwbTime0              = 0x0D,
    HopModeKey            = 0x0E,
    MacMode               = 0x0F,
    VendorSpecific        = 0x10,
    Status                = 0x11
};

struct RangingSessionParameters {
    core::SessionId sessionId{0};
    uint16_t uwbConfigId{0};
    uint8_t pulseShapeCombo{0};
    core::UwbChannel channel{core::UwbChannel::Channel9};
    uint8_t syncCodeIndex{0};
    uint32_t durationMs{0};
    uint16_t slotDurationRstu{0};
    uint8_t slotsPerRound{12};
    core::HoppingMode hoppingMode{core::HoppingMode::Disabled};
    uint8_t hoppingConfigBitmask{0};
    std::array<std::byte, 4> hopModeKey{};
    core::StsIndex stsIndex0{0};
    uint64_t initiationTimeUs{0};
    uint8_t macMode{0};
    uint8_t responderCount{1};
};

struct DeviceCapabilities {
    std::vector<uint16_t> supportedConfigIds{0x0000};
    std::vector<uint8_t> supportedPulseShapes{0x00};
    uint8_t channelBitmask{0x02}; // Channel 9 default
    uint8_t slotBitmask{0x01};    // 3 chaps (1200 rstu) default
    uint32_t syncCodeBitmask{0x00000200}; // Preamble code 9 default
    uint8_t hoppingConfigBitmask{0x18};
    uint8_t minRanMultiplier{1};
    uint8_t macMode{0};
    uint8_t responderCount{1};
};

class SetupMessageCodec {
public:
    [[nodiscard]] static core::Result<std::vector<std::byte>> buildM1(
        core::SessionId sessionId,
        const DeviceCapabilities& caps);

    [[nodiscard]] static core::Result<void> parseM2(
        std::span<const std::byte> payload,
        core::SessionId expectedSessionId,
        const DeviceCapabilities& localCaps,
        RangingSessionParameters& outParams);

    [[nodiscard]] static core::Result<std::vector<std::byte>> buildM3(
        const RangingSessionParameters& params,
        const DeviceCapabilities& localCaps);

    [[nodiscard]] static core::Result<void> parseM4(
        std::span<const std::byte> payload,
        RangingSessionParameters& inOutParams);

    [[nodiscard]] static core::Result<std::vector<std::byte>> buildSuspendResumeRequest(
        core::SessionId sessionId,
        bool isSuspend);

    [[nodiscard]] static core::Result<std::vector<std::byte>> buildSuspendResponse(
        bool accept);
};

} // namespace uwb::protocol::setup
