#include "uwb/protocol/FrameCodec.hpp"
#include <cstring>

namespace uwb::protocol {

namespace {

uint16_t readLe16(const std::byte* p) noexcept {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(p[0]) |
        (static_cast<uint16_t>(p[1]) << 8)
    );
}

uint32_t readLe32(const std::byte* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void writeLe16(uint16_t v, std::byte* p) noexcept {
    p[0] = static_cast<std::byte>(v & 0xFF);
    p[1] = static_cast<std::byte>((v >> 8) & 0xFF);
}

void writeLe32(uint32_t v, std::byte* p) noexcept {
    p[0] = static_cast<std::byte>(v & 0xFF);
    p[1] = static_cast<std::byte>((v >> 8) & 0xFF);
    p[2] = static_cast<std::byte>((v >> 16) & 0xFF);
    p[3] = static_cast<std::byte>((v >> 24) & 0xFF);
}

bool isValidVendorOui(const std::byte* p) noexcept {
    const uint32_t oui = static_cast<uint32_t>(p[0]) |
                        (static_cast<uint32_t>(p[1]) << 8) |
                        (static_cast<uint32_t>(p[2]) << 16);
    return oui == VendorOuiAliro;
}

} // namespace

core::Result<MacHeader> FrameCodec::decodeHeader(std::span<const std::byte> frame) noexcept {
    if (frame.size() < MacHeaderLength) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const std::byte* data = frame.data();

    if (readLe16(&data[0]) != FrameControlField ||
        static_cast<uint8_t>(data[4]) != SecurityControlField ||
        static_cast<uint8_t>(data[13]) != KeyIndexField ||
        readLe16(&data[14]) != VendorIeHeader ||
        !isValidVendorOui(&data[16]) ||
        readLe16(&data[21]) != HeaderTermination2Ie) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    MacHeader header{};
    header.destinationShortAddress = readLe16(&data[2]);
    header.frameCounter = core::FrameCounter{readLe32(&data[5])};
    // Wire is the LE image of KeySourceHigh||KeySourceLow (see encodeHeader); store
    // the canonical {High, Low} order so it compares directly against deriveAddresses.
    for (size_t i = 0; i < 4; ++i) {
        header.keySource[i] = data[12 - i];
    }
    header.messageId = static_cast<MessageIdentifier>(data[19]);
    header.payloadLength = static_cast<uint8_t>(data[20]);

    return header;
}

core::Result<size_t> FrameCodec::encodeHeader(const MacHeader& header, std::span<std::byte> output) noexcept {
    if (output.size() < MacHeaderLength) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    std::byte* p = output.data();

    writeLe16(FrameControlField, &p[0]);
    writeLe16(header.destinationShortAddress, &p[2]);
    p[4] = static_cast<std::byte>(SecurityControlField);
    writeLe32(header.frameCounter.get(), &p[5]);
    for (size_t i = 0; i < 4; ++i) {
        p[9 + i] = header.keySource[3 - i];
    }
    p[13] = static_cast<std::byte>(KeyIndexField);
    writeLe16(VendorIeHeader, &p[14]);
    p[16] = static_cast<std::byte>(VendorOuiAliro & 0xFF);
    p[17] = static_cast<std::byte>((VendorOuiAliro >> 8) & 0xFF);
    p[18] = static_cast<std::byte>((VendorOuiAliro >> 16) & 0xFF);
    p[19] = static_cast<std::byte>(header.messageId);
    p[20] = static_cast<std::byte>(header.payloadLength);
    writeLe16(HeaderTermination2Ie, &p[21]);

    return MacHeaderLength;
}

core::Result<PrePollPayload> FrameCodec::decodePrePoll(std::span<const std::byte> payload) noexcept {
    if (payload.size() < PrePollPayloadLength) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const std::byte* p = payload.data();
    PrePollPayload prePoll{};
    prePoll.sessionId = core::SessionId{readLe32(&p[0])};
    prePoll.pollStsIndex = core::StsIndex{readLe32(&p[4])};
    prePoll.rangingBlock = core::BlockIndex{readLe16(&p[8])};
    prePoll.hopFlag = static_cast<uint8_t>(p[10]);
    prePoll.roundIndex = core::SlotIndex{readLe16(&p[11])};

    return prePoll;
}

core::Result<size_t> FrameCodec::encodePrePoll(const PrePollPayload& prePoll, std::span<std::byte> output) noexcept {
    if (output.size() < PrePollPayloadLength) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    std::byte* p = output.data();
    writeLe32(prePoll.sessionId.get(), &p[0]);
    writeLe32(prePoll.pollStsIndex.get(), &p[4]);
    writeLe16(prePoll.rangingBlock.get(), &p[8]);
    p[10] = static_cast<std::byte>(prePoll.hopFlag);
    writeLe16(prePoll.roundIndex.get(), &p[11]);

    return PrePollPayloadLength;
}

core::Result<FinalDataPayload> FrameCodec::decodeFinalData(std::span<const std::byte> payload) noexcept {
    if (payload.size() < FinalDataHeaderLength) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const std::byte* p = payload.data();
    FinalDataPayload finalData{};
    finalData.sessionId = core::SessionId{readLe32(&p[0])};
    finalData.rangingBlock = core::BlockIndex{readLe16(&p[4])};
    finalData.hopFlag = static_cast<uint8_t>(p[6]);
    finalData.roundIndex = core::SlotIndex{readLe16(&p[7])};
    finalData.finalStsIndex = core::StsIndex{readLe32(&p[9])};
    finalData.pollToFinalTxDeltaDtu = readLe32(&p[13]);

    const auto numResponders = static_cast<uint8_t>(p[17]);
    if (numResponders > MaxRespondersSupported) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const size_t expectedTotalSize = FinalDataHeaderLength + (static_cast<size_t>(numResponders) * ResponderRecordLength);
    if (payload.size() < expectedTotalSize) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    finalData.responderReports.reserve(numResponders);
    for (size_t i = 0; i < numResponders; ++i) {
        const std::byte* r = &payload[FinalDataHeaderLength + (i * ResponderRecordLength)];
        ResponderTimestampReport report{};
        report.responderIndex = static_cast<uint8_t>(r[0]);
        report.pollToResponseDeltaDtu = readLe32(&r[1]);
        report.timestampUncertainty = static_cast<uint8_t>(r[5]);
        report.rangingStatus = static_cast<uint8_t>(r[6]);
        finalData.responderReports.push_back(report);
    }

    return finalData;
}

core::Result<size_t> FrameCodec::encodeFinalData(const FinalDataPayload& finalData, std::span<std::byte> output) noexcept {
    const size_t totalSize = FinalDataHeaderLength + (finalData.responderReports.size() * ResponderRecordLength);
    if (output.size() < totalSize || finalData.responderReports.size() > MaxRespondersSupported) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    std::byte* p = output.data();
    writeLe32(finalData.sessionId.get(), &p[0]);
    writeLe16(finalData.rangingBlock.get(), &p[4]);
    p[6] = static_cast<std::byte>(finalData.hopFlag);
    writeLe16(finalData.roundIndex.get(), &p[7]);
    writeLe32(finalData.finalStsIndex.get(), &p[9]);
    writeLe32(finalData.pollToFinalTxDeltaDtu, &p[13]);
    p[17] = static_cast<std::byte>(finalData.responderReports.size());

    for (size_t i = 0; i < finalData.responderReports.size(); ++i) {
        std::byte* r = &output[FinalDataHeaderLength + (i * ResponderRecordLength)];
        r[0] = static_cast<std::byte>(finalData.responderReports[i].responderIndex);
        writeLe32(finalData.responderReports[i].pollToResponseDeltaDtu, &r[1]);
        r[5] = static_cast<std::byte>(finalData.responderReports[i].timestampUncertainty);
        r[6] = static_cast<std::byte>(finalData.responderReports[i].rangingStatus);
    }

    return totalSize;
}

} // namespace uwb::protocol
