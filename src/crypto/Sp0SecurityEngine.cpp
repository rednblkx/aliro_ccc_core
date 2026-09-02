#include "uwb/crypto/Sp0SecurityEngine.hpp"
#include <algorithm>
#include <cstring>

namespace uwb::crypto {

namespace {

void writeBe32(uint32_t val, std::byte out[4]) noexcept {
    out[0] = static_cast<std::byte>((val >> 24) & 0xFF);
    out[1] = static_cast<std::byte>((val >> 16) & 0xFF);
    out[2] = static_cast<std::byte>((val >> 8) & 0xFF);
    out[3] = static_cast<std::byte>(val & 0xFF);
}

void xorBlocks(std::span<std::byte> out, std::span<const std::byte> a, std::span<const std::byte> b, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

} // namespace

void Sp0SecurityEngine::formatNonce(
    std::span<const std::byte, 8> srcLongAddress,
    core::FrameCounter counter,
    std::array<std::byte, NonceLength>& nonce) noexcept {

    std::memcpy(nonce.data(), srcLongAddress.data(), 8);
    writeBe32(counter.get(), &nonce[8]);
    nonce[12] = static_cast<std::byte>(SecurityLevel);
}

core::Result<void> Sp0SecurityEngine::computeCbcMac(
    std::span<const std::byte, 16> key,
    const std::array<std::byte, NonceLength>& nonce,
    std::span<const std::byte> aad,
    std::span<const std::byte> payload,
    std::array<std::byte, 16>& outMac) {

    // B_0 Block Formation: Flags (0x59) || Nonce (13) || Payload Length (2)
    std::array<std::byte, 16> b0{};
    b0[0] = static_cast<std::byte>(0x59);
    std::memcpy(&b0[1], nonce.data(), NonceLength);
    b0[14] = static_cast<std::byte>((payload.size() >> 8) & 0xFF);
    b0[15] = static_cast<std::byte>(payload.size() & 0xFF);

    auto res = m_crypto.aes128EcbEncrypt(key, b0, outMac);
    if (!res) return std::unexpected(res.error());

    if (!aad.empty()) {
        std::array<std::byte, 16> block{};
        size_t aadOffset = 0;

        block[0] = static_cast<std::byte>((aad.size() >> 8) & 0xFF);
        block[1] = static_cast<std::byte>(aad.size() & 0xFF);

        size_t copyLen = std::min(aad.size(), size_t{14});
        std::memcpy(&block[2], aad.data(), copyLen);
        aadOffset += copyLen;

        xorBlocks(outMac, outMac, block, 16);
        res = m_crypto.aes128EcbEncrypt(key, outMac, outMac);
        if (!res) return std::unexpected(res.error());

        while (aadOffset < aad.size()) {
            block.fill(std::byte{0});
            copyLen = std::min(aad.size() - aadOffset, size_t{16});
            std::memcpy(block.data(), aad.data() + aadOffset, copyLen);
            aadOffset += copyLen;

            xorBlocks(outMac, outMac, block, 16);
            res = m_crypto.aes128EcbEncrypt(key, outMac, outMac);
            if (!res) return std::unexpected(res.error());
        }
    }

    size_t payloadOffset = 0;
    while (payloadOffset < payload.size()) {
        std::array<std::byte, 16> block{};
        size_t copyLen = std::min(payload.size() - payloadOffset, size_t{16});
        std::memcpy(block.data(), payload.data() + payloadOffset, copyLen);
        payloadOffset += copyLen;

        xorBlocks(outMac, outMac, block, 16);
        res = m_crypto.aes128EcbEncrypt(key, outMac, outMac);
        if (!res) return std::unexpected(res.error());
    }

    return {};
}

core::Result<void> Sp0SecurityEngine::applyCtrStream(
    std::span<const std::byte, 16> key,
    const std::array<std::byte, NonceLength>& nonce,
    std::span<const std::byte> input,
    std::span<std::byte> output,
    std::array<std::byte, 16>& outS0) {

    // A_0 Counter Block: Flags (0x01) || Nonce (13) || Counter (0x0000)
    std::array<std::byte, 16> aBlock{};
    aBlock[0] = static_cast<std::byte>(0x01);
    std::memcpy(&aBlock[1], nonce.data(), NonceLength);
    aBlock[14] = std::byte{0x00};
    aBlock[15] = std::byte{0x00};

    auto res = m_crypto.aes128EcbEncrypt(key, aBlock, outS0);
    if (!res) return std::unexpected(res.error());

    size_t offset = 0;
    uint16_t counter = 1;

    while (offset < input.size()) {
        aBlock[14] = static_cast<std::byte>((counter >> 8) & 0xFF);
        aBlock[15] = static_cast<std::byte>(counter & 0xFF);

        std::array<std::byte, 16> s{};
        res = m_crypto.aes128EcbEncrypt(key, aBlock, s);
        if (!res) return std::unexpected(res.error());

        size_t blockLen = std::min(input.size() - offset, size_t{16});
        for (size_t i = 0; i < blockLen; ++i) {
            output[offset + i] = input[offset + i] ^ s[i];
        }

        offset += blockLen;
        counter++;
    }

    return {};
}

core::Result<size_t> Sp0SecurityEngine::encryptPayload(
    std::span<const std::byte, 16> key,
    std::span<const std::byte, 8> srcLongAddress,
    core::FrameCounter counter,
    std::span<const std::byte> headerAuthData,
    std::span<const std::byte> plaintext,
    std::span<std::byte> outCiphertextWithMic) {

    const size_t totalExpected = plaintext.size() + MicLength;
    if (outCiphertextWithMic.size() < totalExpected) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    std::array<std::byte, NonceLength> nonce{};
    formatNonce(srcLongAddress, counter, nonce);

    std::array<std::byte, 16> macTag{};
    auto macRes = computeCbcMac(key, nonce, headerAuthData, plaintext, macTag);
    if (!macRes) return std::unexpected(macRes.error());

    std::array<std::byte, 16> s0{};
    auto ctrRes = applyCtrStream(key, nonce, plaintext, outCiphertextWithMic.subspan(0, plaintext.size()), s0);
    if (!ctrRes) return std::unexpected(ctrRes.error());

    // Encrypt MIC: Tag[0..7] ^ S_0[0..7]
    for (size_t i = 0; i < MicLength; ++i) {
        outCiphertextWithMic[plaintext.size() + i] = macTag[i] ^ s0[i];
    }

    return totalExpected;
}

core::Result<size_t> Sp0SecurityEngine::decryptPayload(
    std::span<const std::byte, 16> key,
    std::span<const std::byte, 8> srcLongAddress,
    core::FrameCounter counter,
    std::span<const std::byte> headerAuthData,
    std::span<const std::byte> ciphertextWithMic,
    std::span<std::byte> outPlaintext) {

    if (ciphertextWithMic.size() < MicLength) {
        return std::unexpected(core::StatusCode::MalformedFrame);
    }

    const size_t payloadLen = ciphertextWithMic.size() - MicLength;
    if (outPlaintext.size() < payloadLen) {
        return std::unexpected(core::StatusCode::BufferOverflow);
    }

    std::array<std::byte, NonceLength> nonce{};
    formatNonce(srcLongAddress, counter, nonce);

    std::array<std::byte, 16> s0{};
    auto ctrRes = applyCtrStream(key, nonce, ciphertextWithMic.subspan(0, payloadLen), outPlaintext.subspan(0, payloadLen), s0);
    if (!ctrRes) return std::unexpected(ctrRes.error());

    std::array<std::byte, 16> calculatedMac{};
    auto macRes = computeCbcMac(key, nonce, headerAuthData, outPlaintext.subspan(0, payloadLen), calculatedMac);
    if (!macRes) return std::unexpected(macRes.error());

    uint8_t diff = 0;
    for (size_t i = 0; i < MicLength; ++i) {
        const auto expectedMicByte = static_cast<uint8_t>(calculatedMac[i] ^ s0[i]);
        const auto receivedMicByte = static_cast<uint8_t>(ciphertextWithMic[payloadLen + i]);
        diff |= static_cast<uint8_t>(expectedMicByte ^ receivedMicByte);
    }

    if (diff != 0) {
        std::fill(outPlaintext.begin(), outPlaintext.end(), std::byte{0});
        return std::unexpected(core::StatusCode::AuthenticationFailed);
    }

    return payloadLen;
}

} // namespace uwb::crypto
