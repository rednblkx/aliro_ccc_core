#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include "StrongType.hpp"

namespace uwb::core {

struct SessionIdTag {};
using SessionId = StrongType<SessionIdTag, uint32_t>;

struct StsIndexTag {};
using StsIndex = StrongType<StsIndexTag, uint32_t>;

struct BlockIndexTag {};
using BlockIndex = StrongType<BlockIndexTag, uint16_t>;

struct SlotIndexTag {};
using SlotIndex = StrongType<SlotIndexTag, uint16_t>;

struct FrameCounterTag {};
using FrameCounter = StrongType<FrameCounterTag, uint32_t>;

struct DeviceTimestampDtuTag {};
using DeviceTimestampDtu = StrongType<DeviceTimestampDtuTag, uint64_t>; // 40-bit UWB DTU ticks

struct DistanceMmTag {};
using DistanceMm = StrongType<DistanceMmTag, int32_t>;

enum class UwbChannel : uint8_t {
    Channel5 = 5,
    Channel9 = 9
};

enum class PreambleCode : uint8_t {
    Code9  = 9,
    Code10 = 10,
    Code11 = 11,
    Code12 = 12
};

enum class SfdType : uint8_t {
    Ieee4a = 0, // Ternary 8-symbol
    Ieee4z = 1  // 4z standard
};

enum class HoppingMode : uint8_t {
    Disabled          = 0x00,
    Enabled           = 0x01,
    ContinuousAes     = 0xA0,
    ContinuousDefault = 0xA1,
    AdaptiveAes       = 0xA2,
    AdaptiveDefault   = 0xA3
};

struct MacAddresses {
    std::array<std::byte, 4> keySource{};
    uint16_t destinationShort{0xFFFF};
    std::array<std::byte, 8> sourceLong{};
};

} // namespace uwb::core
