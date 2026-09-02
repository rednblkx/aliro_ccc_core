#include "uwb/ranging/DistanceEstimator.hpp"
#include <cmath>

namespace uwb::ranging {

int32_t DistanceEstimator::calculateSignedTofTicks(const DoubleSidedTwrTimestamps& ts) noexcept {
    const auto r1 = static_cast<int64_t>(ts.round1Dtu);
    const auto r2 = static_cast<int64_t>(ts.round2Dtu);
    const auto rep1 = static_cast<int64_t>(ts.reply1Dtu);
    const auto rep2 = static_cast<int64_t>(ts.reply2Dtu);

    const int64_t numerator = (r1 * r2) - (rep1 * rep2);
    const int64_t denominator = r1 + r2 + rep1 + rep2;

    if (denominator == 0) {
        return 0;
    }

    return static_cast<int32_t>(numerator / denominator);
}

core::Result<core::DistanceMm> DistanceEstimator::calculateDistance(
    const DoubleSidedTwrTimestamps& timestamps,
    core::DistanceMm antennaDelayBiasMm) noexcept {

    const int64_t totalInterval = static_cast<int64_t>(timestamps.round1Dtu) +
                                  static_cast<int64_t>(timestamps.round2Dtu) +
                                  static_cast<int64_t>(timestamps.reply1Dtu) +
                                  static_cast<int64_t>(timestamps.reply2Dtu);

    if (totalInterval == 0) {
        return std::unexpected(core::StatusCode::InvalidParameter);
    }

    const int32_t tofTicks = calculateSignedTofTicks(timestamps);

    const auto distanceCalculated = static_cast<int32_t>(
        (static_cast<int64_t>(tofTicks) * 4692LL) / 1000LL
    );

    return core::DistanceMm{distanceCalculated + antennaDelayBiasMm.get()};
}

} // namespace uwb::ranging
