#pragma once

#include <cstddef>
#include <span>
#include "uwb/core/StatusCode.hpp"

namespace uwb::crypto {

/**
 * @brief Abstract platform port interface for AES primitive operations.
 */
class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    /**
     * @brief Encrypts a single 16-byte block with AES-128 in ECB mode.
     */
    [[nodiscard]] virtual core::Result<void> aes128EcbEncrypt(
        std::span<const std::byte, 16> key,
        std::span<const std::byte, 16> plaintext,
        std::span<std::byte, 16> ciphertext) = 0;

    /**
     * @brief Encrypts a single 16-byte block with AES-256 in ECB mode.
     */
    [[nodiscard]] virtual core::Result<void> aes256EcbEncrypt(
        std::span<const std::byte, 32> key,
        std::span<const std::byte, 16> plaintext,
        std::span<std::byte, 16> ciphertext) = 0;

    /**
     * @brief Computes NIST SP 800-38B AES-CMAC tag over a message (128-bit or 256-bit key).
     */
    [[nodiscard]] virtual core::Result<void> aesCmac(
        std::span<const std::byte> key,
        std::span<const std::byte> message,
        std::span<std::byte, 16> outTag) = 0;
};

} // namespace uwb::crypto
