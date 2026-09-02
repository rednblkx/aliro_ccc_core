#pragma once

#include <array>
#include <cstddef>
#include <span>
#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"
#include "uwb/crypto/ICryptoProvider.hpp"

namespace uwb::crypto {

class CccKeyDerivationEngine {
public:
    explicit CccKeyDerivationEngine(ICryptoProvider& crypto) noexcept : m_crypto(crypto) {}

    [[nodiscard]] core::Result<std::array<std::byte, 16>> deriveMupsk1(std::span<const std::byte, 32> ursk);
    [[nodiscard]] core::Result<std::array<std::byte, 32>> deriveMupsk2(std::span<const std::byte, 32> ursk);
    [[nodiscard]] core::Result<std::array<std::byte, 32>> deriveMursk(std::span<const std::byte, 32> ursk);

    [[nodiscard]] core::Result<std::array<std::byte, 16>> deriveSaltedHash(
        std::span<const std::byte, 32> ursk,
        std::span<const std::byte> rangingConfig);

    [[nodiscard]] core::Result<core::MacAddresses> deriveAddresses(
        std::span<const std::byte, 32> mupsk2,
        core::StsIndex stsIndex0);

    // Slot-Specific Material (STS Key, STS IV, SP0 Data Encryption Key)
    struct SlotCryptoMaterial {
        std::array<std::byte, 16> durskKey{};
        std::array<std::byte, 16> stsIv{};
        std::array<std::byte, 16> dudskKey{};
    };

    [[nodiscard]] core::Result<SlotCryptoMaterial> deriveSlotKeys(
        std::span<const std::byte, 32> mursk,
        std::span<const std::byte, 16> saltedHash,
        core::StsIndex stsIndex,
        uint16_t slotsPerRound,
        core::StsIndex stsIndex0);

    [[nodiscard]] core::Result<std::array<std::byte, 16>> deriveStsIv(
        std::span<const std::byte, 16> saltedHash,
        core::StsIndex stsIndex) noexcept;

private:
    ICryptoProvider& m_crypto;

    core::Result<void> kdf108(
        std::span<const std::byte> key,
        uint32_t counter,
        std::span<const std::byte> label,
        std::span<const std::byte> context,
        uint32_t lengthBits,
        std::span<std::byte, 16> output);
};

} // namespace uwb::crypto
