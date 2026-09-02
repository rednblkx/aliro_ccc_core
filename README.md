# aliro_ccc_core

Platform-agnostic C++20 library implementing an Aliro UWB ranging **responder** for the Qorvo/Decawave **DW3000** transceiver. It covers the full responder path: CCC key derivation and STS-secured frame handling (Aliro SP0/SP3), the Poll/Response/Final two-way ranging exchange, and range output through a consensus filter. Hardware access is abstracted behind interfaces, so the library runs both on a host (for tests) and on an MCU when the HAL is implemented for the target platform.

## Layout

| Directory | Contents |
|---|---|
| `include/uwb/session` | `RangingSession` — the event-driven state machine tying everything together |
| `include/uwb/transceiver` | `DW3000Controller` — driver wrapper: PHY config, TX/RX, STS, timestamps |
| `include/uwb/crypto` | MbedTLS-backed crypto provider, CCC key derivation engine, SP0 security engine |
| `include/uwb/protocol` | `FrameCodec` (MAC frames), `SetupMessageCodec` (session setup/control messages) |
| `include/uwb/ranging` | `DistanceEstimator`, `HoppingCalculator`, `RangeConsensusFilter` |
| `include/uwb/hal` | `ISpiDevice`, `IGpioPin`, `IClock`, `ILogger` — the hardware seam you implement |
| `include/uwb/core` | `Result`/`StatusCode`, strong types, shared domain types |

## Building

Requires CMake ≥ 3.22 and a C++20 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The first configure fetches dependencies over the network: the DW3000 decadriver, Mbed TLS 3.6.6. To vendor the driver instead, place it at `third_party/dwt_uwb_driver/`.

## Using the library

Add this repository via `FetchContent`/`add_subdirectory` and link `uwb_core` (it transitively exposes Mbed TLS and the decadriver headers).

1. Implement the four `uwb::hal` interfaces for your platform: SPI (with the speed levels your wiring supports), IRQ/reset GPIO pins, a microsecond clock, and optionally a logger.
2. Construct the pieces and hand ownership of the callbacks:

```cpp
#include "uwb/session/RangingSession.hpp"

crypto::MbedTlsCryptoProvider cryptoProvider;
crypto::CccKeyDerivationEngine kdf{cryptoProvider};
crypto::Sp0SecurityEngine sp0{cryptoProvider};
ranging::RangeConsensusFilter filter;
transceiver::DW3000Controller radio{spi, irqPin, resetPin, clock};

radio.initialize();  // probes the DW3000 over SPI

session::RangingSession session{radio, kdf, sp0, filter, clock /*, logger*/};
```

3. Start a session with the 32-byte URSK shared key and the session parameters received over the Aliro setup flow (the same `RangingSessionParameters` that `SetupMessageCodec` parses from RCFG messages):

```cpp
session.start(
    ursk,                                  // std::span<const std::byte, 32>
    params,                                // protocol::setup::RangingSessionParameters
    session::SessionNodeConfig{.responderIndex = 0},  // 0 = primary anchor, 1 = satellite
    [](const session::RangingResult& r) {
        // r.distance (mm), r.blockIndex, r.integrity, r.timestampUs
    });
```

See the ESP32 adapter [here](https://github.com/rednblkx/aliro_ccc_esp/blob/main/ddk_dw3000_channel.cpp) as example.

From then on the library is purely event-driven: call the `ITransceiverListener` methods (`onRxSuccess`, `onRxTimeout`, `onRxError`, `onTxComplete`) from your IRQ/task context when radio events fire — this is what a full `DW3000Controller` integration does for you. `suspend()`, `resume()`, and `stop()` control the session; a `responderIndex` > 0 or a `blockParityFilter` splits work between multiple anchors.

## Layering rules for contributors

- Dependency direction is strictly downward: `session` → `transceiver`/`crypto`/`ranging`/`protocol` → `core`. Platform code stays out; the only hardware coupling is `uwb::hal`.
- Errors return `core::Result<T>` with `StatusCode`s — no exceptions. Domain values use the strong types from `uwb/core/Types.hpp`.
- Keep key derivation and decryption off the radio-arm critical path; the session pre-derives per-slot keys for this reason.
- The build treats warnings as errors-in-spirit (`-Wall -Wextra -Wconversion -Wsign-conversion …`): new code must be warning-clean.

## License

[MIT](LICENSE)

For DW3000 driver see repo [here](https://github.com/br101/dw3000-decadriver-source)
