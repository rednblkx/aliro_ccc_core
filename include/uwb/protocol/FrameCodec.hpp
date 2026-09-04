#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"

namespace uwb::protocol {

inline constexpr size_t MacHeaderLength = 23;
inline constexpr size_t PrePollPayloadLength = 13;
inline constexpr size_t FinalDataHeaderLength = 18;
inline constexpr size_t ResponderRecordLength = 7;
inline constexpr size_t MaxRespondersSupported = 10;

inline constexpr uint16_t FrameControlField = 0x2B49;
inline constexpr uint8_t  SecurityControlField = 0x16;
inline constexpr uint8_t  KeyIndexField = 0xAA;
inline constexpr uint16_t VendorIeHeader = 0x0005;
inline constexpr uint32_t VendorOuiCarConnectivity = 0x04DF69;
inline constexpr uint32_t VendorOuiAliro = 0x4A191B;
inline constexpr uint32_t VendorOuiUltraWideLock = 0x4A191B; // deprecated alias
inline constexpr uint16_t HeaderTermination2Ie = 0x3F80;

enum class MessageIdentifier : uint8_t {
    PrePoll   = 0x01,
    FinalData = 0x02
};

struct MacHeader {
    uint16_t destinationShortAddress{0xFFFF};
    core::FrameCounter frameCounter{0};
    std::array<std::byte, 4> keySource{};
    MessageIdentifier messageId{MessageIdentifier::PrePoll};
    uint8_t payloadLength{0};
};

struct PrePollPayload {
    core::SessionId sessionId{0};
    core::StsIndex pollStsIndex{0};
    core::BlockIndex rangingBlock{0};
    uint8_t hopFlag{0};
    core::SlotIndex roundIndex{0};
};

struct ResponderTimestampReport {
    uint8_t responderIndex{0};
    uint32_t pollToResponseDeltaDtu{0};
    uint8_t timestampUncertainty{0};
    uint8_t rangingStatus{0};
};

struct FinalDataPayload {
    core::SessionId sessionId{0};
    core::BlockIndex rangingBlock{0};
    uint8_t hopFlag{0};
    core::SlotIndex roundIndex{0};
    core::StsIndex finalStsIndex{0};
    uint32_t pollToFinalTxDeltaDtu{0};
    std::vector<ResponderTimestampReport> responderReports{};
};

class FrameCodec {
public:
    [[nodiscard]] static core::Result<MacHeader> decodeHeader(std::span<const std::byte> frame) noexcept;
    [[nodiscard]] static core::Result<size_t> encodeHeader(const MacHeader& header, std::span<std::byte> output) noexcept;

    [[nodiscard]] static core::Result<PrePollPayload> decodePrePoll(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] static core::Result<size_t> encodePrePoll(const PrePollPayload& prePoll, std::span<std::byte> output) noexcept;

    [[nodiscard]] static core::Result<FinalDataPayload> decodeFinalData(std::span<const std::byte> payload) noexcept;
    [[nodiscard]] static core::Result<size_t> encodeFinalData(const FinalDataPayload& finalData, std::span<std::byte> output) noexcept;
};

} // namespace uwb::protocol
