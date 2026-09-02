#include "uwb/crypto/CccKeyDerivationEngine.hpp"
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

uint32_t readBe32(const std::byte in[4]) noexcept {
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) |
           (static_cast<uint32_t>(in[3]));
}

constexpr std::byte LabelUpsk[] = {std::byte{'U'}, std::byte{'P'}, std::byte{'S'}, std::byte{'K'}};
constexpr std::byte LabelUrsk[] = {std::byte{'U'}, std::byte{'R'}, std::byte{'S'}, std::byte{'K'}};
constexpr std::byte LabelUdsk[] = {std::byte{'U'}, std::byte{'D'}, std::byte{'S'}, std::byte{'K'}};
constexpr std::byte LabelSalt[] = {std::byte{'S'}, std::byte{'A'}, std::byte{'L'}, std::byte{'T'}};
constexpr std::byte LabelUrskKt[] = {std::byte{'U'}, std::byte{'R'}, std::byte{'S'}, std::byte{'K'}, std::byte{'_'}, std::byte{'K'}, std::byte{'T'}};
constexpr std::byte LabelUad[] = {std::byte{'U'}, std::byte{'A'}, std::byte{'D'}};
constexpr std::byte ZeroContext3[3] = {std::byte{0}, std::byte{0}, std::byte{0}};

void sanitizeReservedAddress(std::span<std::byte> addr) noexcept {
    bool isReserved = false;
    if (addr.size() == 2) {
        isReserved = (addr[0] == static_cast<std::byte>(0xFF) &&
                     (static_cast<uint8_t>(addr[1]) >= 0xFE));
    } else {
        isReserved = std::all_of(addr.begin(), addr.end(), [](std::byte b) {
            return b == static_cast<std::byte>(0xFF);
        });
    }
    if (isReserved) {
        addr[0] &= static_cast<std::byte>(0x7F);
    }
}

} // namespace

core::Result<void> CccKeyDerivationEngine::kdf108(
    std::span<const std::byte> key,
    uint32_t counter,
    std::span<const std::byte> label,
    std::span<const std::byte> context,
    uint32_t lengthBits,
    std::span<std::byte, 16> output) {

    std::array<std::byte, 64> buffer{};
    size_t offset = 0;

    writeBe32(counter, &buffer[offset]);
    offset += 4;

    std::memcpy(&buffer[offset], label.data(), label.size());
    offset += label.size();

    buffer[offset++] = std::byte{0x00};

    if (!context.empty()) {
        std::memcpy(&buffer[offset], context.data(), context.size());
        offset += context.size();
    }

    writeBe32(lengthBits, &buffer[offset]);
    offset += 4;

    return m_crypto.aesCmac(key, std::span<const std::byte>(buffer.data(), offset), output);
}

core::Result<std::array<std::byte, 16>> CccKeyDerivationEngine::deriveMupsk1(std::span<const std::byte, 32> ursk) {
    std::array<std::byte, 16> mupsk1{};
    auto res = kdf108(ursk, 1, LabelUpsk, ZeroContext3, 384, mupsk1);
    if (!res) return std::unexpected(res.error());
    return mupsk1;
}

core::Result<std::array<std::byte, 32>> CccKeyDerivationEngine::deriveMupsk2(std::span<const std::byte, 32> ursk) {
    std::array<std::byte, 32> mupsk2{};
    std::span<std::byte, 16> part1(mupsk2.data(), 16);
    std::span<std::byte, 16> part2(mupsk2.data() + 16, 16);

    auto res1 = kdf108(ursk, 2, LabelUpsk, ZeroContext3, 384, part1);
    if (!res1) return std::unexpected(res1.error());

    auto res2 = kdf108(ursk, 3, LabelUpsk, ZeroContext3, 384, part2);
    if (!res2) return std::unexpected(res2.error());

    return mupsk2;
}

core::Result<std::array<std::byte, 32>> CccKeyDerivationEngine::deriveMursk(std::span<const std::byte, 32> ursk) {
    std::array<std::byte, 32> mursk{};
    std::span<std::byte, 16> part1(mursk.data(), 16);
    std::span<std::byte, 16> part2(mursk.data() + 16, 16);

    auto res1 = kdf108(ursk, 1, LabelUrsk, ZeroContext3, 256, part1);
    if (!res1) return std::unexpected(res1.error());

    auto res2 = kdf108(ursk, 2, LabelUrsk, ZeroContext3, 256, part2);
    if (!res2) return std::unexpected(res2.error());

    return mursk;
}

core::Result<std::array<std::byte, 16>> CccKeyDerivationEngine::deriveSaltedHash(
    std::span<const std::byte, 32> ursk,
    std::span<const std::byte> rangingConfig) {

    std::array<std::byte, 16> salt{};
    auto res = kdf108(ursk, 1, LabelSalt, ZeroContext3, 128, salt);
    if (!res) return std::unexpected(res.error());

    std::array<std::byte, 32> paddedSalt{};
    std::memcpy(&paddedSalt[16], salt.data(), 16);

    std::array<std::byte, 16> saltedHash{};
    auto cmacRes = m_crypto.aesCmac(paddedSalt, rangingConfig, saltedHash);
    if (!cmacRes) return std::unexpected(cmacRes.error());

    return saltedHash;
}

core::Result<core::MacAddresses> CccKeyDerivationEngine::deriveAddresses(
    std::span<const std::byte, 32> mupsk2,
    core::StsIndex stsIndex0) {

    std::array<std::byte, 4> ctx{};
    writeBe32(stsIndex0.get(), ctx.data());

    std::array<std::byte, 16> uad{};
    auto res = kdf108(mupsk2, 1, LabelUad, ctx, 128, uad);
    if (!res) return std::unexpected(res.error());

    std::array<std::byte, 2> ksLow = {uad[0], uad[1]};
    std::array<std::byte, 2> ksHigh = {uad[2], uad[3]};
    std::array<std::byte, 2> destShort = {uad[4], uad[5]};
    std::array<std::byte, 8> srcLong{};
    std::memcpy(srcLong.data(), &uad[6], 8);

    sanitizeReservedAddress(ksLow);
    sanitizeReservedAddress(ksHigh);
    sanitizeReservedAddress(destShort);
    sanitizeReservedAddress(srcLong);

    core::MacAddresses addrs{};
    addrs.keySource = {ksHigh[0], ksHigh[1], ksLow[0], ksLow[1]};
    addrs.destinationShort = static_cast<uint16_t>((static_cast<uint16_t>(destShort[0]) << 8) | static_cast<uint16_t>(destShort[1]));
    addrs.sourceLong = srcLong;

    return addrs;
}

core::Result<CccKeyDerivationEngine::SlotCryptoMaterial> CccKeyDerivationEngine::deriveSlotKeys(
        std::span<const std::byte, 32> mursk,
        std::span<const std::byte, 16> saltedHash,
        core::StsIndex stsIndex,
        uint16_t slotsPerRound,
        core::StsIndex stsIndex0) {
    if (slotsPerRound == 0) {
        return std::unexpected(core::StatusCode::InvalidParameter);
    }
    const uint32_t relative = stsIndex.get() - stsIndex0.get();
    const uint32_t baseStsIndex = stsIndex.get() - (relative % slotsPerRound);

    std::array<std::byte, 32> bitContext{};
    for (int b = 0; b < 32; ++b) {
        bitContext[static_cast<size_t>(b)] = static_cast<std::byte>((baseStsIndex >> (31 - b)) & 1);
    }

    std::array<std::byte, 32> urskKt{};
    std::span<std::byte, 16> kt1(urskKt.data(), 16);
    std::span<std::byte, 16> kt2(urskKt.data() + 16, 16);

    auto res1 = kdf108(mursk, 1, LabelUrskKt, bitContext, 256, kt1);
    if (!res1) return std::unexpected(res1.error());

    auto res2 = kdf108(mursk, 2, LabelUrskKt, bitContext, 256, kt2);
    if (!res2) return std::unexpected(res2.error());

    std::array<std::byte, 19> dkeyContext{};
    std::memcpy(dkeyContext.data(), saltedHash.data(), 16);

    SlotCryptoMaterial material{};
    auto durskRes = kdf108(urskKt, 1, LabelUrsk, dkeyContext, 128, material.durskKey);
    if (!durskRes) return std::unexpected(durskRes.error());

    auto dudskRes = kdf108(urskKt, 1, LabelUdsk, dkeyContext, 128, material.dudskKey);
    if (!dudskRes) return std::unexpected(dudskRes.error());

    auto ivRes = deriveStsIv(saltedHash, stsIndex);
    if (!ivRes) return std::unexpected(ivRes.error());
    material.stsIv = *ivRes;

    return material;
}

core::Result<std::array<std::byte, 16>> CccKeyDerivationEngine::deriveStsIv(
    std::span<const std::byte, 16> saltedHash,
    core::StsIndex stsIndex) noexcept {

    std::array<std::byte, 16> iv{};
    std::memcpy(iv.data(), saltedHash.data(), 16);

    // V_counter = SaltedHash[8..11] + sts_index
    const uint32_t vCounter = readBe32(&iv[8]) + stsIndex.get();
    writeBe32(vCounter, &iv[8]);

    return iv;
}

} // namespace uwb::crypto
