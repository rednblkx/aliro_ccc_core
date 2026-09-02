#pragma once

#include <concepts>
#include <compare>
#include <utility>

namespace uwb::core {

/**
 * @brief Zero-overhead strong type wrapper preventing parameter swapping
 *        and enforcing semantic correctness.
 */
template <typename Tag, typename T>
class StrongType {
public:
    using ValueType = T;

    constexpr StrongType() = default;
    constexpr explicit StrongType(const T& val) : m_value(val) {}
    constexpr explicit StrongType(T&& val) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_value(std::move(val)) {}

    [[nodiscard]] constexpr T& get() noexcept { return m_value; }
    [[nodiscard]] constexpr const T& get() const noexcept { return m_value; }

    [[nodiscard]] constexpr explicit operator T() const noexcept { return m_value; }

    constexpr auto operator<=>(const StrongType&) const = default;
    constexpr bool operator==(const StrongType&) const = default;

private:
    T m_value{};
};

} // namespace uwb::core
