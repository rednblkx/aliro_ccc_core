#pragma once

#include "uwb/core/Types.hpp"

namespace uwb::ranging {

class HoppingCalculator {
public:
    static constexpr uint32_t HoppingModulus = 65521; // Largest prime below 2^16

    /**
     * @brief Computes the pseudo-random round index for a given ranging block.
     * 
     * @param blockIndex Current block index
     * @param hopKeyRw 32-bit random hop key negotiated during setup
     * @param roundsPerBlock Total number of rounds per ranging block
     * @return core::SlotIndex The calculated hop round offset
     */
    [[nodiscard]] static core::SlotIndex calculateRoundIndex(
        core::BlockIndex blockIndex,
        uint32_t hopKeyRw,
        uint16_t roundsPerBlock) noexcept;
};

} // namespace uwb::ranging
