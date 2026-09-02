#include "uwb/protocol/SetupMessageCodec.hpp"
#include <algorithm>
#include <cstring>

namespace uwb::protocol::setup {

namespace {

// Bit 7 = No Hopping, Bit 6 = Continuous AES, Bit 5 = Continuous Default, Bit 4 = Adaptive AES, Bit 3 = Adaptive Default
constexpr uint8_t HopCccToFira(uint8_t ccc) noexcept { return ccc >> 3; }
constexpr uint8_t HopFiraToCcc(uint8_t fira) noexcept { return static_cast<uint8_t>(fira << 3); }

constexpr uint8_t HopCapAes        = (1 << 0);
constexpr uint8_t HopCapDefault    = (1 << 1);
constexpr uint8_t HopCapAdaptive   = (1 << 2);
constexpr uint8_t HopCapContinuous = (1 << 3);
constexpr uint8_t HopCapNoHopping  = (1 << 4);

constexpr uint8_t HopComboContinuousDefault = (HopCapContinuous | HopCapDefault); // 0x0A -> 0x50 CCC
constexpr uint8_t HopComboAdaptiveDefault   = (HopCapAdaptive | HopCapDefault);   // 0x06 -> 0x30 CCC
constexpr uint8_t HopComboNoHopping         = (HopCapNoHopping);                   // 0x10 -> 0x80 CCC

void writeBe16(uint16_t v, std::byte* p) noexcept {
    p[0] = static_cast<std::byte>((v >> 8) & 0xFF);
    p[1] = static_cast<std::byte>(v & 0xFF);
}

void writeBe32(uint32_t v, std::byte* p) noexcept {
    p[0] = static_cast<std::byte>((v >> 24) & 0xFF);
    p[1] = static_cast<std::byte>((v >> 16) & 0xFF);
    p[2] = static_cast<std::byte>((v >> 8) & 0xFF);
    p[3] = static_cast<std::byte>(v & 0xFF);
}

void writeBe64(uint64_t v, std::byte* p) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::byte>(v & 0xFF);
        v >>= 8;
    }
}

uint16_t readBe16(const std::byte* p) noexcept {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) |
        static_cast<uint16_t>(p[1])
    );
}

uint32_t readBe32(const std::byte* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

uint64_t readBe64(const std::byte* p) noexcept {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint8_t>(p[i]);
    }
    return v;
}

class TlvWriter {
public:
    explicit TlvWriter(ProtocolCategory cat, MessageType msgType) {
        m_buffer.resize(4);
        m_buffer[0] = static_cast<std::byte>(cat);
        m_buffer[1] = static_cast<std::byte>(msgType);
    }

    void addU8(AttributeTag tag, uint8_t val) {
        m_buffer.push_back(static_cast<std::byte>(tag));
        m_buffer.push_back(std::byte{1});
        m_buffer.push_back(static_cast<std::byte>(val));
    }

    void addU16(AttributeTag tag, uint16_t val) {
        m_buffer.push_back(static_cast<std::byte>(tag));
        m_buffer.push_back(std::byte{2});
        const size_t sz = m_buffer.size();
        m_buffer.resize(sz + 2);
        writeBe16(val, &m_buffer[sz]);
    }

    void addU32(AttributeTag tag, uint32_t val) {
        m_buffer.push_back(static_cast<std::byte>(tag));
        m_buffer.push_back(std::byte{4});
        const size_t sz = m_buffer.size();
        m_buffer.resize(sz + 4);
        writeBe32(val, &m_buffer[sz]);
    }

    void addBytes(AttributeTag tag, std::span<const std::byte> bytes) {
        m_buffer.push_back(static_cast<std::byte>(tag));
        m_buffer.push_back(static_cast<std::byte>(bytes.size()));
        m_buffer.insert(m_buffer.end(), bytes.begin(), bytes.end());
    }

    void addU16Array(AttributeTag tag, std::span<const uint16_t> values) {
        m_buffer.push_back(static_cast<std::byte>(tag));
        m_buffer.push_back(static_cast<std::byte>(values.size() * 2));
        for (uint16_t v : values) {
            std::byte buf[2];
            writeBe16(v, buf);
            m_buffer.push_back(buf[0]);
            m_buffer.push_back(buf[1]);
        }
    }

    std::vector<std::byte> finalize() {
        const auto payloadLen = static_cast<uint16_t>(m_buffer.size() - 4);
        writeBe16(payloadLen, &m_buffer[2]);
        return std::move(m_buffer);
    }

private:
    std::vector<std::byte> m_buffer;
};

struct TlvElement {
    AttributeTag tag;
    std::span<const std::byte> value;
};

core::Result<std::vector<TlvElement>> parseTlvStream(std::span<const std::byte> stream) {
    if (stream.size() < 4) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const uint16_t payloadLen = readBe16(&stream[2]);
    if (stream.size() - 4 < payloadLen) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    std::vector<TlvElement> elements;
    size_t offset = 4;
    const size_t end = 4 + payloadLen;

    while (offset < end) {
        if (offset + 2 > end) {
            return std::unexpected(core::StatusCode::MalformedFrame);
        }
        const auto tag = static_cast<AttributeTag>(stream[offset]);
        const auto len = static_cast<uint8_t>(stream[offset + 1]);
        offset += 2;

        if (offset + len > end) {
            return std::unexpected(core::StatusCode::MalformedFrame);
        }
        elements.push_back(TlvElement{tag, stream.subspan(offset, len)});
        offset += len;
    }

    return elements;
}

} // namespace

core::Result<std::vector<std::byte>> SetupMessageCodec::buildM1(
    core::SessionId sessionId,
    const DeviceCapabilities& caps) {

    TlvWriter writer(ProtocolCategory::UwbRangingService, MessageType::RangingSetupM1);

    writer.addU16Array(AttributeTag::ConfigId, caps.supportedConfigIds);

    std::vector<std::byte> pulseShapes(caps.supportedPulseShapes.size());
    for (size_t i = 0; i < pulseShapes.size(); ++i) {
        pulseShapes[i] = static_cast<std::byte>(caps.supportedPulseShapes[i]);
    }
    writer.addBytes(AttributeTag::PulseShapeCombo, pulseShapes);
    writer.addU8(AttributeTag::ChannelBitmask, caps.channelBitmask);
    writer.addU32(AttributeTag::SessionId, sessionId.get());

    return writer.finalize();
}

core::Result<void> SetupMessageCodec::parseM2(
    std::span<const std::byte> payload,
    core::SessionId expectedSessionId,
    const DeviceCapabilities& localCaps,
    RangingSessionParameters& outParams) {

    auto elements = parseTlvStream(payload);
    if (!elements) return std::unexpected(elements.error());

    outParams.slotsPerRound = 12;

    for (const auto& elem : *elements) {
        switch (elem.tag) {
            case AttributeTag::ConfigId:
                if (elem.value.size() != 2) return std::unexpected(core::StatusCode::MalformedFrame);
                outParams.uwbConfigId = readBe16(elem.value.data());
                break;
            case AttributeTag::PulseShapeCombo:
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                outParams.pulseShapeCombo = static_cast<uint8_t>(elem.value[0]);
                break;
            case AttributeTag::SessionId: {
                if (elem.value.size() != 4) return std::unexpected(core::StatusCode::MalformedFrame);
                const auto sessionId = core::SessionId{readBe32(elem.value.data())};
                if (sessionId != expectedSessionId) {
                    return std::unexpected(core::StatusCode::InvalidParameter);
                }
                outParams.sessionId = sessionId;
                break;
            }
            case AttributeTag::ChannelBitmask: {
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                const auto chMask = static_cast<uint8_t>(elem.value[0]);
                const auto common = chMask & localCaps.channelBitmask;
                if (common & 0x02) {
                    outParams.channel = core::UwbChannel::Channel9;
                } else if (common & 0x01) {
                    outParams.channel = core::UwbChannel::Channel5;
                } else {
                    return std::unexpected(core::StatusCode::InvalidParameter);
                }
                break;
            }
            case AttributeTag::RanMultiplier: {
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                const auto peerMultiplier = static_cast<uint8_t>(elem.value[0]);
                const uint8_t selected = std::max(peerMultiplier, localCaps.minRanMultiplier);
                outParams.durationMs = 96U * selected;
                break;
            }
            case AttributeTag::SlotBitmask: {
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                const auto peerSlotMask = static_cast<uint8_t>(elem.value[0]);
                const uint8_t common = peerSlotMask & localCaps.slotBitmask;
                uint8_t chaps = 3;
                for (uint8_t idx = 0; idx < 7; ++idx) {
                    if ((common >> idx) & 0x01) {
                        switch (idx) {
                            case 0: chaps = 3; break;
                            case 1: chaps = 4; break;
                            case 2: chaps = 6; break;
                            case 3: chaps = 8; break;
                            case 4: chaps = 9; break;
                            case 5: chaps = 12; break;
                            case 6: chaps = 24; break;
                        }
                        break;
                    }
                }
                outParams.slotDurationRstu = static_cast<uint16_t>(400U * chaps);
                break;
            }
            case AttributeTag::HoppingConfigBitmask: {
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                const auto peerCcc = static_cast<uint8_t>(elem.value[0]);
                const uint8_t peerFira = HopCccToFira(peerCcc);
                const uint8_t common = peerFira & localCaps.hoppingConfigBitmask;

                // Negotiate single selected mode: Disabled (0x80) preferred — the responder
                // does not implement the hopping schedule (HOP Mode Key from M4 is unused),
                // and a hopping exchange makes the per-block Poll STS index unpredictable.
                // Fall back to Continuous Default (0x50) if the peer offers nothing else.
                if ((common & HopComboNoHopping) == HopComboNoHopping) {
                    outParams.hoppingMode = core::HoppingMode::Disabled;
                    outParams.hoppingConfigBitmask = HopFiraToCcc(HopComboNoHopping); // 0x80
                } else if ((common & HopComboContinuousDefault) == HopComboContinuousDefault) {
                    outParams.hoppingMode = core::HoppingMode::ContinuousDefault;
                    outParams.hoppingConfigBitmask = HopFiraToCcc(HopComboContinuousDefault); // 0x50
                } else {
                    return std::unexpected(core::StatusCode::InvalidParameter);
                }
                break;
            }
            default:
                break;
        }
    }

    return {};
}

core::Result<std::vector<std::byte>> SetupMessageCodec::buildM3(
    const RangingSessionParameters& params,
    const DeviceCapabilities& localCaps) {

    TlvWriter writer(ProtocolCategory::UwbRangingService, MessageType::RangingSetupM3);

    const auto ranMultiplier = static_cast<uint8_t>(params.durationMs / 96);
    const auto chapsPerSlot = static_cast<uint8_t>(params.slotDurationRstu / 400);

    writer.addU8(AttributeTag::RanMultiplier, ranMultiplier);                     // Tag 0x04
    writer.addU8(AttributeTag::ChapsPerSlot, chapsPerSlot);                       // Tag 0x09
    writer.addU8(AttributeTag::NumResponders, localCaps.responderCount);          // Tag 0x0A
    writer.addU8(AttributeTag::SlotsPerRound, params.slotsPerRound);              // Tag 0x0B
    writer.addU32(AttributeTag::SyncCodeIndexBitmask, localCaps.syncCodeBitmask); // Tag 0x06 (e.g. 0x00000F00)
    writer.addU8(AttributeTag::HoppingConfigBitmask, params.hoppingConfigBitmask);// Tag 0x08 (0x50 or 0x80)
    writer.addU8(AttributeTag::MacMode, localCaps.macMode);                       // Tag 0x0F (0x00)

    return writer.finalize();
}

core::Result<void> SetupMessageCodec::parseM4(
    std::span<const std::byte> payload,
    RangingSessionParameters& inOutParams) {

    auto elements = parseTlvStream(payload);
    if (!elements) return std::unexpected(elements.error());

    for (const auto& elem : *elements) {
        switch (elem.tag) {
            case AttributeTag::StsIndex0:
                if (elem.value.size() != 4) return std::unexpected(core::StatusCode::MalformedFrame);
                inOutParams.stsIndex0 = core::StsIndex{readBe32(elem.value.data())};
                break;
            case AttributeTag::UwbTime0:
                if (elem.value.size() != 8) return std::unexpected(core::StatusCode::MalformedFrame);
                inOutParams.initiationTimeUs = readBe64(elem.value.data());
                break;
            case AttributeTag::HopModeKey:
                if (elem.value.size() != 4) return std::unexpected(core::StatusCode::MalformedFrame);
                std::memcpy(inOutParams.hopModeKey.data(), elem.value.data(), 4);
                break;
            case AttributeTag::SyncCodeIndex:
                if (elem.value.size() != 1) return std::unexpected(core::StatusCode::MalformedFrame);
                inOutParams.syncCodeIndex = static_cast<uint8_t>(elem.value[0]);
                break;
            default:
                break;
        }
    }

    return {};
}

core::Result<std::vector<std::byte>> SetupMessageCodec::buildSuspendResumeRequest(
    core::SessionId sessionId,
    bool isSuspend) {

    TlvWriter writer(
        ProtocolCategory::UwbRangingService,
        isSuspend ? MessageType::SuspendRequest : MessageType::ResumeRequest
    );
    writer.addU32(AttributeTag::SessionId, sessionId.get());
    return writer.finalize();
}

core::Result<std::vector<std::byte>> SetupMessageCodec::buildSuspendResponse(bool accept) {
    TlvWriter writer(ProtocolCategory::UwbRangingService, MessageType::SuspendResponse);
    writer.addU8(AttributeTag::Status, accept ? 0x00 : 0x01);
    return writer.finalize();
}

} // namespace uwb::protocol::setup