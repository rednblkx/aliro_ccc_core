#pragma once

#include <optional>
#include "uwb/core/Types.hpp"

namespace uwb::ranging {

struct RangeIntegrityReport {
    core::DistanceMm distance{0};
    bool isPlausible{false};
    bool stsQualityPassed{false};
    int16_t stsQualityIndex{0};
    uint8_t consecutiveAgreeingCount{0};
    uint8_t stsValidStreak{0};
    bool isTrusted{false};
};

struct RangeConsensusConfig {
    core::DistanceMm minPlausibleDistance{-300};     // -30 cm (near-field tolerance)
    core::DistanceMm maxPlausibleDistance{30000};    // 30 meters
    core::DistanceMm maxConsecutiveSpreadMm{500};    // 50 cm max delta
    uint8_t requiredConsensusCount{3};               // K = 3
    int16_t minimumStsQualityThreshold{0};
};

class RangeConsensusFilter {
public:
    using Configuration = RangeConsensusConfig;

    explicit RangeConsensusFilter(const Configuration& config = Configuration{}) noexcept
        : m_config(config) {}

    void reset() noexcept;

    RangeIntegrityReport ingest(
        core::DistanceMm distance,
        int32_t driverVerdict,
        int16_t stsQualityMetric) noexcept;

    [[nodiscard]] std::optional<core::DistanceMm> latestTrustedDistance() const noexcept;
    [[nodiscard]] bool isTrusted() const noexcept;
    [[nodiscard]] uint8_t trustConfidenceScore() const noexcept;

private:
    Configuration m_config;
    std::optional<core::DistanceMm> m_lastDistance;
    uint8_t m_agreeingStreak{0};
    uint8_t m_stsPassedStreak{0};
    int16_t m_lowestQualityInStreak{0};
    bool m_trusted{false};

    [[nodiscard]] bool evaluatePlausibility(core::DistanceMm distance) const noexcept;
    [[nodiscard]] bool evaluateStsQuality(int32_t driverVerdict, int16_t qualityIndex) const noexcept;
};

} // namespace uwb::ranging
