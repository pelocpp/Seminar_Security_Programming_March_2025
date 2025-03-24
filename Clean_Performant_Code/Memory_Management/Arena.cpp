// ===========================================================================
// Arena.cpp
// ===========================================================================

#include "Arena.h"

#include <memory>
#include <iostream>
#include <print>
#include <vector>
#include <set>

auto arena = Arena<1024>{};   // TO : Ist arena eine Kopie ??????????????????


class User {
public:
    auto operator new(size_t size) -> void* {
        return arena.allocate(size);
    }
    auto operator delete(void* p) -> void {
        arena.deallocate(static_cast<std::byte*>(p), sizeof(User));
    }
    auto operator new[](size_t size) -> void* {
        return arena.allocate(size);
    }
    auto operator delete[](void* p, size_t size) -> void {
        arena.deallocate(static_cast<std::byte*>(p), size);
    }

private:
    int m_id{}; // need same data in this class
};

void memory_management_arena_01()
{
    size_t n{ 1 };

    for (size_t i{}; i != 64; ++i) {

        size_t tmp{ arena.align_up(i) };
        std::println("{:2} => {:3}", i, tmp);
    }
}

void memory_management_arena_02()
{
    auto p1 = arena.allocate(2);
    auto p2 = arena.allocate(2);

    // es muessen die zuletzt allokierten Bereiche als erstes zurückgegeben werden !!!
    arena.deallocate(static_cast<std::byte*>(p2), 2);
    arena.deallocate(static_cast<std::byte*>(p1), 2);
}

void memory_management_arena_03()
{
    // No dynamic memory is allocated when we create the users
    auto user1 = new User{};
    delete user1;

    auto users = new User[10];
    delete[] users;

    auto user2 = std::make_unique<User>();
}

void memory_management_arena_04()
{
    auto user = std::make_shared<User>();

    auto users = std::vector<User>{};
    users.reserve(10);
}

// ===========================================================================
// Custom Allocator

template<typename T>
struct Alloc {
    using value_type = T;
    Alloc();
    template<typename U> Alloc(const Alloc<U>&);
    T* allocate(size_t n);
    auto deallocate(T*, size_t) const noexcept -> void;
};
template<typename T>
auto operator==(const Alloc<T>&, const Alloc<T>&) -> bool;
template<typename T>
auto operator!=(const Alloc<T>&, const Alloc<T>&) -> bool;


// ===========================================================================
// Custom Allocator


//#include <iostream>
//#include <set>
//#include <gtest/gtest.h>
//#include "arena.h"
//

template <class T, size_t N>
struct ShortAlloc {
    using value_type = T;
    using arena_type = Arena<N>;
    ShortAlloc(const ShortAlloc&) = default;
    ShortAlloc& operator=(const ShortAlloc&) = default;
    ShortAlloc(arena_type& arena) noexcept : arena_{ &arena } {}
    template <class U>
    ShortAlloc(const ShortAlloc<U, N>& other) noexcept
        : arena_{ other.arena_ } {
    }
    template <class U> struct rebind {
        using other = ShortAlloc<U, N>;
    };
    auto allocate(size_t n) -> T* {
        return reinterpret_cast<T*>(arena_->allocate(n * sizeof(T)));
    }
    auto deallocate(T* p, size_t n) noexcept -> void {
        arena_->deallocate(reinterpret_cast<std::byte*>(p), n * sizeof(T));
    }
    template <class U, size_t M>
    auto operator==(const ShortAlloc<U, M>& other) const noexcept {
        return N == M && arena_ == other.arena_;
    }
    template <class U, size_t M>
    auto operator!=(const ShortAlloc<U, M>& other) const noexcept {
        return !(*this == other);
    }
    template <class U, size_t M> friend struct ShortAlloc;

private:
    arena_type* arena_;
};

void memory_management_arena_05()
{
    using SmallSet = std::set<int, std::less<int>, ShortAlloc<int, 512>>;

    auto stack_arena = SmallSet::allocator_type::arena_type{}; // [auto&& is needed in current version of MSVC] // KOPIE ????
    
    auto unique_numbers = SmallSet{ stack_arena };

    unique_numbers.insert(3);
    unique_numbers.insert(4);
    unique_numbers.insert(2);
    unique_numbers.insert(4);
    unique_numbers.insert(1);
    unique_numbers.insert(3);
    unique_numbers.insert(3);

    // Print unique numbers
    for (const auto& number : unique_numbers) {
        std::cout << number << '\n';
    }

   // ASSERT_EQ(4, unique_numbers.size());
    auto unique_number = unique_numbers.begin();
    for (size_t i = 1; i <= unique_numbers.size(); ++i) {
    //   ASSERT_EQ(i, *unique_number);
        ++unique_number;
    }
}




void memory_management_arena()
{
    // memory_management_arena_01();
    //memory_management_arena_02();
    //memory_management_arena_03();
    //memory_management_arena_04();
    memory_management_arena_05();
}

// ===========================================================================
// End-of-File
// ===========================================================================
