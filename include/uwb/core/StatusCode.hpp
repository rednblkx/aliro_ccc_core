#pragma once

#include <cstdint>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>

namespace uwb::core {

enum class StatusCode : uint32_t {
    Success = 0,
    InvalidParameter,
    CryptoOperationFailed,
    AuthenticationFailed,
    BufferOverflow,
    MalformedFrame,
    ReplayDetected,
    HardwareTimeout,
    TransceiverError,
    LateTransmission,
    StsCorrelationFailed,
    SessionSuspended,
    InvalidState,
    ConsensusNotReached,
    OutOfMemory
};

[[nodiscard]] constexpr std::string_view statusToString(StatusCode code) noexcept {
    switch (code) {
        case StatusCode::Success:                return "Success";
        case StatusCode::InvalidParameter:       return "InvalidParameter";
        case StatusCode::CryptoOperationFailed:  return "CryptoOperationFailed";
        case StatusCode::AuthenticationFailed:   return "AuthenticationFailed";
        case StatusCode::BufferOverflow:         return "BufferOverflow";
        case StatusCode::MalformedFrame:         return "MalformedFrame";
        case StatusCode::ReplayDetected:         return "ReplayDetected";
        case StatusCode::HardwareTimeout:        return "HardwareTimeout";
        case StatusCode::TransceiverError:       return "TransceiverError";
        case StatusCode::LateTransmission:       return "LateTransmission";
        case StatusCode::StsCorrelationFailed:   return "StsCorrelationFailed";
        case StatusCode::SessionSuspended:       return "SessionSuspended";
        case StatusCode::InvalidState:           return "InvalidState";
        case StatusCode::ConsensusNotReached:    return "ConsensusNotReached";
        case StatusCode::OutOfMemory:            return "OutOfMemory";
    }
    return "UnknownError";
}

template <typename E>
class Unexpected {
public:
    constexpr explicit Unexpected(const E& err) : m_error(err) {}
    constexpr explicit Unexpected(E&& err) : m_error(std::move(err)) {}
    [[nodiscard]] constexpr const E& error() const noexcept { return m_error; }
    [[nodiscard]] constexpr E& error() noexcept { return m_error; }
    [[nodiscard]] constexpr const E& value() const noexcept { return m_error; }
private:
    E m_error;
};

template <typename E>
[[nodiscard]] constexpr Unexpected<std::decay_t<E>> unexpected(E&& e) {
    return Unexpected<std::decay_t<E>>(std::forward<E>(e));
}

template <typename T, typename E = StatusCode>
class Result {
public:
    using ValueType = T;
    using ErrorType = E;

    constexpr Result(const T& val) : m_hasValue(true) {
        new (&m_storage.val) T(val);
    }

    constexpr Result(T&& val) noexcept(std::is_nothrow_move_constructible_v<T>) : m_hasValue(true) {
        new (&m_storage.val) T(std::move(val));
    }

    constexpr Result(const Unexpected<E>& unexp) : m_hasValue(false) {
        new (&m_storage.err) E(unexp.error());
    }

    constexpr Result(Unexpected<E>&& unexp) noexcept(std::is_nothrow_move_constructible_v<E>) : m_hasValue(false) {
        new (&m_storage.err) E(std::move(unexp.error()));
    }

    constexpr Result(const Result& other) : m_hasValue(other.m_hasValue) {
        if (m_hasValue) {
            new (&m_storage.val) T(other.m_storage.val);
        } else {
            new (&m_storage.err) E(other.m_storage.err);
        }
    }

    constexpr Result(Result&& other) noexcept(std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>)
        : m_hasValue(other.m_hasValue) {
        if (m_hasValue) {
            new (&m_storage.val) T(std::move(other.m_storage.val));
        } else {
            new (&m_storage.err) E(std::move(other.m_storage.err));
        }
    }

    constexpr Result& operator=(const Result& other) {
        if (this != &other) {
            this->~Result();
            new (this) Result(other);
        }
        return *this;
    }

    constexpr Result& operator=(Result&& other) noexcept {
        if (this != &other) {
            this->~Result();
            new (this) Result(std::move(other));
        }
        return *this;
    }

    ~Result() {
        if (m_hasValue) {
            m_storage.val.~T();
        } else {
            m_storage.err.~E();
        }
    }

    [[nodiscard]] constexpr bool has_value() const noexcept { return m_hasValue; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return m_hasValue; }

    [[nodiscard]] constexpr T& value() & { return m_storage.val; }
    [[nodiscard]] constexpr const T& value() const& { return m_storage.val; }
    [[nodiscard]] constexpr T&& value() && { return std::move(m_storage.val); }

    [[nodiscard]] constexpr T& operator*() & noexcept { return m_storage.val; }
    [[nodiscard]] constexpr const T& operator*() const& noexcept { return m_storage.val; }
    [[nodiscard]] constexpr T* operator->() noexcept { return &m_storage.val; }
    [[nodiscard]] constexpr const T* operator->() const noexcept { return &m_storage.val; }

    [[nodiscard]] constexpr const E& error() const& noexcept { return m_storage.err; }
    [[nodiscard]] constexpr E& error() & noexcept { return m_storage.err; }

private:
    union Storage {
        T val;
        E err;
        constexpr Storage() {}
        ~Storage() {}
    } m_storage;
    bool m_hasValue;
};

template <typename E>
class Result<void, E> {
public:
    using ValueType = void;
    using ErrorType = E;

    constexpr Result() noexcept : m_hasValue(true), m_err(E{}) {}
    constexpr Result(const Unexpected<E>& unexp) noexcept : m_hasValue(false), m_err(unexp.error()) {}
    constexpr Result(Unexpected<E>&& unexp) noexcept : m_hasValue(false), m_err(std::move(unexp.error())) {}

    [[nodiscard]] constexpr bool has_value() const noexcept { return m_hasValue; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return m_hasValue; }
    constexpr void value() const noexcept {}

    [[nodiscard]] constexpr const E& error() const noexcept { return m_err; }
    [[nodiscard]] constexpr E& error() noexcept { return m_err; }

private:
    bool m_hasValue;
    E m_err;
};

} // namespace uwb::core

namespace std {
    using uwb::core::unexpected;
}
