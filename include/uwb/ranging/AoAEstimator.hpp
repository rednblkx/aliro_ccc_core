#pragma once

#include <cstdint>
#include "uwb/core/Types.hpp"

namespace uwb::ranging {

struct AoAEstimate {
    int32_t centiDegrees{0}; // AoA in 1/100 deg (positive = one side of the array; sign
                             // convention follows the DW3220 PDoA register)
    bool valid{false};
};

class AoAEstimator {
public:
    // Raw PDoA fixed-point format: signed Q11 (1:-11), radians. See DW3000 user manual
    // CIA_TDOA_1_PDOA register description
    static constexpr double PdoaQ11Scale = 2048.0;

    // Carrier wavelengths (mm) per UWB channel: c / f_center
    // ch9 = 7987.2 MHz -> 37.521 mm, ch5 = 6489.6 MHz -> 46.190 mm
    static constexpr double WavelengthChannel9Mm = 37.521;
    static constexpr double WavelengthChannel5Mm = 46.190;

    /**
     * @brief Converts a raw hardware PDoA reading into an AoA estimate.
     *
     * AoA = asin(pdoa_rad * lambda / (2*pi*d))
     *
     * NOTE on ambiguity: with the 2-port array the raw PDoA spans [-pi, +pi], so the
     * unambiguous angular range is asin(±lambda/(2d)) — ±54.4 deg on channel 9 with the
     * default 23.1 mm spacing (±90 deg on channel 5 where d == lambda/2). Angles beyond
     * that fold back into the range; front/back ambiguity is inherent to 2-port PDoA.
     *
     * @param pdoaRaw Signed Q11 PDoA value from the transceiver (RxSuccessEvent::pdoaRaw)
     * @param channel Ranging channel (selects the carrier wavelength)
     * @param antennaSpacingMm Antenna center-to-center spacing in mm (float, e.g. 23.1);
     *                         <= 0 disables the estimate
     * @return AoAEstimate with valid=false when disabled
     */
    [[nodiscard]] static AoAEstimate fromPdoa(
        int16_t pdoaRaw,
        core::UwbChannel channel,
        float antennaSpacingMm) noexcept;
};

} // namespace uwb::ranging
