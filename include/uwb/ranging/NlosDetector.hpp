#pragma once

#include <cstdint>

namespace uwb::ranging {

// First-path-power NLOS classification.
//
// Compares the power carried by the first arriving path (F1^2+F2^2+F3^2 of the
// channel impulse response, Q8.8 dBm as returned by the DW3000 driver's
// dwt_calculate_first_path_power) against the total channel power
// (dwt_calculate_rssi, same Q8.8 scale). In line-of-sight the first path
// dominates and the two sit within a few dB; under NLOS the direct path is
// attenuated by the obstructing material while the late multipath energy is
// not, so RSSI exceeds the first-path power. A positive difference beyond the
// configured margin classifies the sample NLOS.
//
// All values are Q8.8 fixed point (256 == 1.0 dB, 0.1 dB precision) — the
// native output scale of the driver's power routines; no float is used so the
// detector is usable on the ranging hot path.
struct NlosSample {
    int16_t firstPathPowerDbQ8{0};
    int16_t rssiDbQ8{0};
};

struct NlosConfig {
    // RSSI minus first-path power above which a sample is NLOS, Q8.8 dB.
    int16_t nlosMarginDbQ8{static_cast<int16_t>(10 * 256)};
};

struct NlosVerdict {
    bool valid{false};      // diagnostics were readable and non-degenerate
    bool nlos{false};
};

class NlosDetector {
public:
    explicit NlosDetector(const NlosConfig& config = NlosConfig{}) noexcept
        : m_config(config) {}

    // Classify one sample. Invalid covers unreadable diagnostics and the
    // driver's SHRT_MIN error sentinel (returned when power or accumulation
    // count is zero) — those must never be treated as evidence either way.
    // Ordinary dBm powers are negative, so negativity itself is valid data.
    [[nodiscard]] NlosVerdict evaluate(const NlosSample& sample) const noexcept {
        if (sample.firstPathPowerDbQ8 == INT16_MIN ||
            sample.rssiDbQ8 == INT16_MIN ||
            sample.firstPathPowerDbQ8 == 0 ||
            sample.rssiDbQ8 == 0) {
            return NlosVerdict{.valid = false, .nlos = false};
        }
        const int32_t excess =
            static_cast<int32_t>(sample.rssiDbQ8) - sample.firstPathPowerDbQ8;
        return NlosVerdict{
            .valid = true,
            .nlos = excess > static_cast<int32_t>(m_config.nlosMarginDbQ8)
        };
    }

private:
    NlosConfig m_config;
};

} // namespace uwb::ranging
