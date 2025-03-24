// ===========================================================================
// Arena.cpp
// ===========================================================================

#pragma once

#include <cstddef>
#include <cstdint>

template <size_t N>
class Arena {

    static constexpr size_t alignment = alignof(std::max_align_t);

private:
    alignas(alignment) std::byte m_buffer[N];
    std::byte* m_ptr{};

public:
    Arena() noexcept : m_ptr(m_buffer) {}

    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;

    auto reset() noexcept { m_ptr = m_buffer; }
    static constexpr auto size() noexcept { return N; }
    auto used() const noexcept { return static_cast<size_t>(m_ptr - m_buffer); }
    auto allocate(size_t n) -> std::byte*;
    auto deallocate(std::byte* p, size_t n) noexcept -> void;

// private:
public:
    static auto align_up(size_t n) noexcept -> size_t {
        return (n + (alignment - 1)) & ~(alignment - 1);
    }

    // private:
    auto pointer_in_buffer(const std::byte* p) const noexcept -> bool {
        return std::uintptr_t(m_buffer) <= std::uintptr_t(p) &&
            std::uintptr_t(p) < std::uintptr_t(m_buffer) + N;
    }
};

template <size_t N> auto Arena<N>::allocate(size_t n) -> std::byte* {
    const auto aligned_n = align_up(n);
    const auto available_bytes =
        static_cast<decltype(aligned_n)>(m_buffer + N - m_ptr);
    if (available_bytes >= aligned_n) {
        auto* r = m_ptr;
        m_ptr += aligned_n;
        return r;
    }
    return nullptr;
}

template <size_t N>
auto Arena<N>::deallocate(std::byte* p, size_t n) noexcept -> void {
    if (pointer_in_buffer(p)) {
        n = align_up(n);
        if (p + n == m_ptr) {
            m_ptr = p;
        }
    }
}

// ===========================================================================
// End-of-File
// ===========================================================================
