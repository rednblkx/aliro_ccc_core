#include "uwb/ranging/AoAEstimator.hpp"
#include <cmath>

namespace uwb::ranging {

AoAEstimate AoAEstimator::fromPdoa(
    int16_t pdoaRaw,
    core::UwbChannel channel,
    float antennaSpacingMm) noexcept {

    AoAEstimate out{};
    if (antennaSpacingMm <= 0.0f) {
        return out; // AoA disabled / spacing not configured
    }

    const double wavelengthMm = (channel == core::UwbChannel::Channel5)
                                    ? WavelengthChannel5Mm
                                    : WavelengthChannel9Mm;

    const double pdoaRad = static_cast<double>(pdoaRaw) / PdoaQ11Scale;
    const double domainArg = pdoaRad * wavelengthMm / (2.0 * M_PI * antennaSpacingMm);

    // Beyond |1| the angle would exceed the array's unambiguous range — clamp to the
    // edge (the true angle has folded; see header note)
    const double clamped = std::max(-1.0, std::min(1.0, domainArg));
    const double aoaRad = std::asin(clamped);

    out.centiDegrees = static_cast<int32_t>(std::lround(aoaRad * (180.0 / M_PI) * 100.0));
    out.valid = true;
    return out;
}

} // namespace uwb::ranging
