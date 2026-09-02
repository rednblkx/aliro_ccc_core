#include "uwb/ranging/HoppingCalculator.hpp"

namespace uwb::ranging {

core::SlotIndex HoppingCalculator::calculateRoundIndex(
    core::BlockIndex blockIndex,
    uint32_t hopKeyRw,
    uint16_t roundsPerBlock) noexcept {

    if (roundsPerBlock == 0) {
        return core::SlotIndex{0};
    }

    uint64_t t = (static_cast<uint64_t>(blockIndex.get()) + hopKeyRw) & 0xFFFFULL;

    t = (t * t) % HoppingModulus;

    const auto roundIndex = static_cast<uint16_t>((t * roundsPerBlock) >> 16);

    return core::SlotIndex{roundIndex};
}

} // namespace uwb::ranging
