#pragma once

#include "uwb/core/StatusCode.hpp"
#include "uwb/core/Types.hpp"

namespace uwb::ranging {

struct DoubleSidedTwrTimestamps {
    uint32_t round1Dtu{0}; // T_round1 = Initiator Round Time (Poll Tx -> Resp Rx)
    uint32_t reply1Dtu{0}; // T_reply1 = Responder Reply Time (Poll Rx -> Resp Tx)
    uint32_t round2Dtu{0}; // T_round2 = Responder Round Time (Resp Tx -> Final Rx)
    uint32_t reply2Dtu{0}; // T_reply2 = Initiator Reply Time (Resp Rx -> Final Tx)
};

class DistanceEstimator {
public:
    // Speed of light in millimeters per picosecond (c = 299,792,458 m/s = 0.299792458 mm/ps)
    static constexpr double SpeedOfLightMmPerPs = 0.299792458;

    // DW3000 device time unit (DTU): 1 tick = 1 / (499.2 MHz * 128) ≈ 15.651041666667 ps
    static constexpr double DtuPeriodPs = 1000000.0 / (499.2 * 128.0);

    // Millimeters per DTU tick: (c * DtuPeriodPs) ≈ 4.692051 mm/tick
    static constexpr double MmPerDtuTick = SpeedOfLightMmPerPs * DtuPeriodPs;

    /**
     * @brief Computes the signed Time-of-Flight in device timestamp ticks.
     * Formula: (T_round1 * T_round2 - T_reply1 * T_reply2) / (T_round1 + T_round2 + T_reply1 + T_reply2)
     */
    [[nodiscard]] static int32_t calculateSignedTofTicks(const DoubleSidedTwrTimestamps& timestamps) noexcept;

    /**
     * @brief Computes the corrected physical distance in millimeters.
     */
    [[nodiscard]] static core::Result<core::DistanceMm> calculateDistance(
        const DoubleSidedTwrTimestamps& timestamps,
        core::DistanceMm antennaDelayBiasMm = core::DistanceMm{0}) noexcept;
};

} // namespace uwb::ranging
