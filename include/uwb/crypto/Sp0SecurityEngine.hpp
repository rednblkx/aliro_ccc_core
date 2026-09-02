#pragma once

#include <array>
#include <cstddef>
#include <span>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"
#include "uwb/crypto/ICryptoProvider.hpp"

namespace uwb::crypto {

class Sp0SecurityEngine {
public:
    static constexpr size_t MicLength = 8;
    static constexpr size_t NonceLength = 13;
    static constexpr uint8_t SecurityLevel = 0x06;

    explicit Sp0SecurityEngine(ICryptoProvider& crypto) noexcept : m_crypto(crypto) {}

    [[nodiscard]] core::Result<size_t> encryptPayload(
        std::span<const std::byte, 16> key,
        std::span<const std::byte, 8> srcLongAddress,
        core::FrameCounter counter,
        std::span<const std::byte> headerAuthData,
        std::span<const std::byte> plaintext,
        std::span<std::byte> outCiphertextWithMic);

    [[nodiscard]] core::Result<size_t> decryptPayload(
        std::span<const std::byte, 16> key,
        std::span<const std::byte, 8> srcLongAddress,
        core::FrameCounter counter,
        std::span<const std::byte> headerAuthData,
        std::span<const std::byte> ciphertextWithMic,
        std::span<std::byte> outPlaintext);

private:
    ICryptoProvider& m_crypto;

    static void formatNonce(
        std::span<const std::byte, 8> srcLongAddress,
        core::FrameCounter counter,
        std::array<std::byte, NonceLength>& nonce) noexcept;

    core::Result<void> computeCbcMac(
        std::span<const std::byte, 16> key,
        const std::array<std::byte, NonceLength>& nonce,
        std::span<const std::byte> aad,
        std::span<const std::byte> payload,
        std::array<std::byte, 16>& outMac);

    core::Result<void> applyCtrStream(
        std::span<const std::byte, 16> key,
        const std::array<std::byte, NonceLength>& nonce,
        std::span<const std::byte> input,
        std::span<std::byte> output,
        std::array<std::byte, 16>& outS0);
};

} // namespace uwb::crypto
