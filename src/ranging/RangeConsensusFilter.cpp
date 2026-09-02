#include "uwb/ranging/RangeConsensusFilter.hpp"
#include <algorithm>
#include <cstdlib>

namespace uwb::ranging {

void RangeConsensusFilter::reset() noexcept {
    m_lastDistance.reset();
    m_agreeingStreak = 0;
    m_stsPassedStreak = 0;
    m_lowestQualityInStreak = 0;
    m_trusted = false;
}

bool RangeConsensusFilter::evaluatePlausibility(core::DistanceMm distance) const noexcept {
    return distance.get() >= m_config.minPlausibleDistance.get() &&
           distance.get() <= m_config.maxPlausibleDistance.get();
}

bool RangeConsensusFilter::evaluateStsQuality(int32_t driverVerdict, int16_t qualityIndex) const noexcept {
    return driverVerdict >= 0 && qualityIndex >= m_config.minimumStsQualityThreshold;
}

RangeIntegrityReport RangeConsensusFilter::ingest(
    core::DistanceMm distance,
    int32_t driverVerdict,
    int16_t stsQualityMetric) noexcept {

    RangeIntegrityReport report{};
    report.distance = distance;
    report.stsQualityIndex = stsQualityMetric;

    report.isPlausible = evaluatePlausibility(distance);
    if (!report.isPlausible) {
        reset();
        return report;
    }

    if (distance.get() < 0) {
        distance = core::DistanceMm{0};
        report.distance = distance;
    }

    report.stsQualityPassed = evaluateStsQuality(driverVerdict, stsQualityMetric);
    if (report.stsQualityPassed) {
        if (m_stsPassedStreak == 0 || stsQualityMetric < m_lowestQualityInStreak) {
            m_lowestQualityInStreak = stsQualityMetric;
        }
        if (m_stsPassedStreak < m_config.requiredConsensusCount) {
            m_stsPassedStreak++;
        }
    } else {
        m_stsPassedStreak = 0;
        m_lowestQualityInStreak = stsQualityMetric;
    }
    report.stsValidStreak = m_stsPassedStreak;

    if (m_lastDistance.has_value()) {
        const int32_t delta = std::abs(distance.get() - m_lastDistance->get());
        if (delta <= m_config.maxConsecutiveSpreadMm.get()) {
            if (m_agreeingStreak < m_config.requiredConsensusCount) {
                m_agreeingStreak++;
            }
        } else {
            m_agreeingStreak = 1;
        }
    } else {
        m_agreeingStreak = 1;
    }

    m_lastDistance = distance;
    report.consecutiveAgreeingCount = m_agreeingStreak;

    m_trusted = (m_agreeingStreak >= m_config.requiredConsensusCount);
    report.isTrusted = m_trusted;

    return report;
}

std::optional<core::DistanceMm> RangeConsensusFilter::latestTrustedDistance() const noexcept {
    if (m_trusted && m_lastDistance.has_value()) {
        return m_lastDistance;
    }
    return std::nullopt;
}

bool RangeConsensusFilter::isTrusted() const noexcept {
    return m_trusted;
}

uint8_t RangeConsensusFilter::trustConfidenceScore() const noexcept {
    return m_agreeingStreak;
}

} // namespace uwb::ranging
