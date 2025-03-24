// ===========================================================================
// STL_Algorithms.cpp
// ===========================================================================

#include "../LoggerUtility/ScopedTimer.h"

#include <algorithm>
#include <forward_list>
#include <iterator>
#include <list>
#include <numeric>
#include <print>
#include <string>
#include <vector>

namespace STLAlgorithms {

    // -----------------------------------------------------------------------

    static void test_initializing()
    {
        std::vector<int> values(10);

        std::fill(
            values.begin(),
            values.end(),
            123
        );
    }

    // -----------------------------------------------------------------------

    static void test_iterating()
    {
        const auto values = std::vector{ 9, 7, 1, 2, 3, 8, 10, 4, 5, 6 };

        std::for_each(
            values.begin(),
            values.end(), 
            [](auto i) { std::print("{} ", i); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static void test_generating()
    {
        auto values = std::vector<int>(10);

        std::generate(
            values.begin(),
            values.end(),
            [n = 0]() mutable { ++n;  return 2 * n; }
        );

        std::for_each(
            values.begin(),
            values.end(),
            [](auto i) { std::print("{} ", i); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static void test_generating_indices()
    {
        auto values = std::vector<int>(10);

        std::iota(
            values.begin(),
            values.end(),
            1
        );

        std::for_each(
            values.begin(),
            values.end(),
            [](auto i) { std::print("{} ", i); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static void test_copying()
    {
        std::vector<int> source(10, 123);
        std::vector<int> target(10);

        std::copy(
            source.begin(),
            source.end(),
            target.begin()
        );

        std::for_each(
            target.begin(),
            target.end(),
            [](auto i) { std::print("{} ", i); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static void test_transforming()
    {
        const std::list<std::string> source {
            "1.5", "2.5", "3.5", "4.5", "5.5", "6.5", "7.5", "8.5", "9.5", "10.5"
        };
        
        std::vector<double> target;

        std::transform(
            source.begin(),
            source.end(),
            std::back_inserter(target),
            [](const auto& entry) {
                return std::stod(entry);
            }
        );

        std::for_each(
            target.begin(),
            target.end(),
            [](auto n) { std::print("{} ", n); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static std::string toString(const auto& vec) {
        return std::accumulate(
            vec.begin(),
            vec.end(),
            std::string{},
            [](const std::string& s, auto next) mutable {
                return s + std::to_string(next);
            }
        );
    }

    static void test_accumulate()
    {
        const auto values = std::vector{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        std::string s{ toString(values) };
        std::println("{}", s);
    }

    // -----------------------------------------------------------------------

    static void test_sorting()
    {
        auto values = std::vector{ 9, 7, 1, 2, 3, 8, 10, 4, 5, 6 };

        std::sort(
            values.begin(),
            values.end()
        );

        std::for_each(
            values.begin(),
            values.end(),
            [](auto i) { std::print("{} ", i); }
        );
        std::println();

        std::sort(
            values.begin(),
            values.end(),
            [](auto n, auto m) { return n > m; }
        );

        std::for_each(
            values.begin(),
            values.end(),
            [](auto i) { std::print("{} ", i); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------

    static void test_finding()
    {
        const auto values = std::list{ 9, 7, 1, 2, 3, 8, 10, 4, 5, 6 };

        auto it = std::find(
            values.begin(),
            values.end(),
            3
        );

        if (it != values.end()) {
            std::println("Found {} ", *it);
        }
    }

    // -----------------------------------------------------------------------

    static void test_finding_binary()
    {
        const auto values = std::list{ 1, 1, 2, 2, 3, 3, 4, 4, 5, 5 };

        if (!std::is_sorted(values.begin(), values.end())) {
            std::println("Container is not sorted!");
            return;
        }

        auto elem{ 3 };

        auto found = std::binary_search(
            values.begin(),
            values.end(),
            elem
        );

        if (found) {
            std::println("Found {} ", elem);
        }
    }

    // -----------------------------------------------------------------------

    static void test_some_condition()
    {
        const auto values = std::vector{ 3, 2, 2, -1, 0, 2, 1 };

        auto noNegative = std::none_of(
            values.begin(),
            values.end(),
            [](int n) { return n < 0; }
        );

        if (noNegative) {
            std::println("Contains only positive numbers");
        }

        auto allPositive = std::all_of(
            values.begin(),
            values.end(),
            [](int n) { return n >= 0; }
        );

        if (allPositive) {
            std::println("Contains only positive numbers");
        }

        auto anyNegative = std::any_of(
            values.begin(),
            values.end(),
            [](int n) { return n < 0; }
        );

        if (anyNegative) {
            std::println("Contains at least one negative number");
        }
    }

    // -----------------------------------------------------------------------

    static void test_counting()
    {
        const auto values = std::list{ 3, 3, 2, 1, 3, 1, 3 };
        auto elem{ 3 };

        auto n = std::count(
            values.begin(),
            values.end(),
            elem
        );

        std::println("Found {} elements of value {}", elem, n);
    }

    // -----------------------------------------------------------------------

    static void test_counting_binary()
    {
        const auto values = std::list{ 1, 1, 2, 2, 3, 3, 4, 4, 5, 5 };

        if (!std::is_sorted(values.begin(), values.end())) {
            std::println("Container is not sorted!");
            return;
        }

        auto elem{ 3 };

        auto range = std::equal_range(
            values.begin(),
            values.end(),
            elem
        );

        const auto& [begin, end] = range;
        auto count = std::distance(begin, end);
        std::println("Found {} elements of value {}", count, elem);
    }

    // -----------------------------------------------------------------------

    static auto some_func()
    {
        return 123;
    }

    static auto another_func()
    {
        return 456;
    }
    
    static void test_min_max_clamp()
    {
        const auto n = std::min(some_func(), another_func());
        std::println("Minimum: {}", n);

        const auto m = std::max(some_func(), another_func());
        std::println("Maximum: {}", m);

        const auto x = std::clamp(some_func(), 100, 200);
        std::println("Clamped Value: {}", x);

        const auto y = std::clamp(some_func(), 50, 100);
        std::println("Clamped Value: {}", y);

        const auto z = std::clamp(some_func(), 150, 200);
        std::println("Clamped Value: {}", z);
    }

    // -----------------------------------------------------------------------

    static void test_min_max()
    {
        const auto values = std::vector{ 4, 2, 1, 7, 3, 1, 5 };

        const auto [min, max] = std::minmax_element(values.begin(), values.end());

        std::println("Minimum: {}, Maximum: {}", *min, *max);

        auto minIndex = std::distance(values.begin(), min);
        std::println("minIndex: {}", minIndex);

        auto maxIndex = std::distance(values.begin(), max);
        std::println("minIndex: {}", maxIndex);
    }
}

namespace STLAlgorithms_BestPractices {

    // -----------------------------------------------------------------------
    // non-generic vs. generic functions

    static auto contains(const std::vector<int>& vec, int elem) {

        for (size_t i{}; i != vec.size(); ++i) {
            if (vec[i] == elem) {
                return true;
            }
        }
        return false;
    }

    template <typename TIterator, typename TValue>
    static auto contains(TIterator begin, TIterator end, const TValue& elem) {

        for (auto it{ begin }; it != end; ++it) {
            if (*it == elem) {
                return true;
            }
        }
        return false;
    }

    static void test_non_generic_vs_generic_function ()
    {
        const auto values1{ std::vector{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } };
        const auto values2{ std::list{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } };
        std::list<std::string> values3{ "1.5", "2.5", "3.5", "4.5", "5.5" };

        bool result1{ contains (values1, 3)};
        //bool result2{ contains(values2, 3) };
        //bool result3{ contains(values3, 3) };

        bool found1{ contains(values1.begin(), values1.end(), 3) };
        bool found2{ contains(values2.begin(), values2.end(), 3) };
        bool found3{ contains(values3.begin(), values3.end(), "3.5")};

        std::println("Found: {}", found1);
        std::println("Found: {}", found2);
        std::println("Found: {}", found3);
    }

    // -----------------------------------------------------------------------
    // Data structures exposing the begin() and end() iterators

    class Grid
    {
    public:
        Grid() : Grid{ 0, 0} {}

        Grid(size_t width, size_t height) : m_width{ width }, m_height{ height }
        {
            m_data.resize(width * height);
        }

        auto getData() // returns whole grid as iterator pairs
        {
            auto left = m_data.begin();
            auto right = m_data.begin() + m_width * m_height;
            return std::make_pair(left, right);
        }

        auto getRow(size_t i) // returns iterator pair for corresponding row
        {
            auto left = m_data.begin() + m_width * i;
            auto right = left + m_width;
            return std::make_pair(left, right);
        }
        
        auto print() 
        {
            std::for_each(
                m_data.begin(),
                m_data.end(),
                [this, i=0, j=0] (auto elem) mutable {
                
                    std::print("[{}:{}] {:2}  ", i, j, m_data[m_width * i + j]);

                    ++j;
                    if (j == m_width) {
                        ++i;
                        j = 0;
                        std::println();
                    }
                }
            );
        }

        auto getWidth() const { return m_width; }
        auto getHeight() const { return m_height; }

    private:
        std::vector<int> m_data;
        size_t           m_width;
        size_t           m_height;
    };

    static void test_grid_01()
    {
        auto grid = Grid{ 5, 5 };

        auto data{ grid.getData() };
        auto& [begin, end] = data;

        std::iota(begin, end, 1);
        grid.print();

        auto numFives = std::count(begin, end, 5);
        std::println("Found {} fives.", numFives);
    }

    static void test_grid_02()
    {
        auto grid = Grid{ 5, 5 };

        auto data{ grid.getData() };
        auto& [begin, end] = data;

        std::generate(begin, end, [] () { return 1; });

        auto row = grid.getRow(2);
        auto& [rowBegin, rowEnd] = row;
        std::generate(rowBegin, rowEnd, []() { return 2; });
        grid.print();

        auto numTwos = std::count(begin, end, 2);
        std::println("Found {} two's.", numTwos);
    }

    static void test_grid()
    {
        test_grid_01();
        test_grid_02();
    }

    // -----------------------------------------------------------------------
    // Use standard algorithms over raw for-loops

    static bool varies(const auto& n) {
        return false;
    }

    static void test_using_raw_for_loop(const auto& infos, const auto& output) {

        // original version using a for-loop
        auto conflicting = false;
        for (const auto& info : infos) {
            if (info.params() == output.params()) {
                if (varies(info.flags())) {
                    conflicting = true;
                    break;
                }
            }
            else {
                conflicting = true;
                break;
            }
        }
    }

    static void test_using_standard_algorithms(const auto& infos, const auto& output) {

        // version using standard algorithms
        const auto in_conflict = [&](const auto& info) {
            return info.params() != output.params() || varies(info.flags());
        };

        const auto conflicting = std::any_of(infos.begin(), infos.end(), in_conflict);
    }

    static void test_use_standard_algorithms_over_raw_for_loops() {

        struct Input
        {
            auto params() const { return 0; }
            auto flags() const { return 0ul; }
        };

        struct Output
        {
            int params() const { return 0; }
        };

        const std::vector<Input> input{ 0 };

        test_using_raw_for_loop(input, Output{});
        test_using_standard_algorithms(input, Output{});
    }

    // -----------------------------------------------------------------------
    // Unexpected exceptions and performance problems

    template <typename TContainer>
    static auto move_n_elements_to_back(TContainer& cont, std::size_t n) {

        // copy the first n elements to the end of the container
        for (auto it = cont.begin(); it != std::next(cont.begin(), n); ++it) {
            cont.emplace_back(std::move(*it));
        }

        // erase the copied elements from front of container
        cont.erase(cont.begin(), std::next(cont.begin(), n));
    }

    template <typename TContainer>
    static auto move_n_elements_to_back_safe(TContainer& cont, std::size_t n) {

        // copy the first n elements to the end of the container
        for (size_t i{}; i != n; ++i) {

            auto pos{ std::next(cont.begin(), i) };
            auto value = *pos;
            cont.emplace_back(std::move(value));
        }

        // erase the copied elements from front of container
        cont.erase(cont.begin(), std::next(cont.begin(), n));
    }

    template <typename TContainer>
    static auto move_n_elements_to_back_safe_and_fast(TContainer& cont, std::size_t n) {

        auto newBegin = std::next(cont.begin(), n);
        std::rotate(cont.begin(), newBegin, cont.end());
    }

    static void test_move_n_elements_to_back()
    {
        auto values = std::vector{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        // move_n_elements_to_back<std::vector<int>>(values, 3); // remove comment // crashes (!!!)
        move_n_elements_to_back_safe<std::vector<int>>(values, 3);

        std::for_each(
            values.begin(),
            values.end(),
            [](auto n) { std::print("{} ", n); }
        );
        std::println();
    }

    // -----------------------------------------------------------------------
    // Optimization Techniques of STL algorithms

    template <typename TIterator, typename TValue>
    static auto find_slow(TIterator first, TIterator last, const TValue& value) {
        for (auto it = first; it != last; ++it) {
            if (*it == value) {
                return it;
            }
        }
        return last;
    }

    template <typename TIterator, typename TValue>
    static auto find_fast(TIterator first, TIterator last, const TValue& value) {
        
        // main loop unrolled into chunks of four (std::random_access_iterator needed)
        auto num_trips = (last - first) / 4;

        for (auto trip_count = num_trips; trip_count > 0; --trip_count) {

            if (*first == value) { return first; } ++first;
            if (*first == value) { return first; } ++first;
            if (*first == value) { return first; } ++first;
            if (*first == value) { return first; } ++first;
        }

        // handle the remaining elements
        switch (last - first) {
            case 3: if (*first == value) { return first; } ++first;
            case 2: if (*first == value) { return first; } ++first;
            case 1: if (*first == value) { return first; } ++first;
            case 0:
            default: return last;
        }
    }

    static void test_optimization_techniques()
    {
        constexpr size_t Size = 10'000'000;      // debug mode
        // constexpr size_t Size = 500'000'000;  // release mode
        //constexpr size_t Size = 10;            // test mode

        std::vector <int> vec;
        vec.resize(Size, 123);

        {
            ScopedTimer watch;
            auto found{ find_slow(vec.begin(), vec.end(), 1'000)};
            std::println("find_slow: {}", (found == vec.end()) ? "Not found" : "Found!");
        }

        {
            ScopedTimer watch;
            auto found{ find_fast(vec.begin(), vec.end(), 1'000) };
            std::println("find_fast: {}", (found == vec.end()) ? "Not found" : "Found!");
        }
    }
}

// =================================================================

static void test_algorithms_introduction()
{
    using namespace STLAlgorithms;
    test_initializing();
    test_iterating();
    test_generating();
    test_generating_indices();
    test_copying();
    test_transforming();
    test_accumulate();
    test_sorting();
    test_finding();
    test_finding_binary();
    test_some_condition();
    test_counting();
    test_counting_binary();
    test_min_max_clamp();
    test_min_max();
}

static void test_algorithms_best_practices()
{
    using namespace STLAlgorithms_BestPractices;

    //test_non_generic_vs_generic_function();
    //test_grid();
    //test_use_standard_algorithms_over_raw_for_loops();
    //test_move_n_elements_to_back();
    test_optimization_techniques();
}

void test_algorithms()
{
    //test_algorithms_introduction();
    test_algorithms_best_practices();
}

// ===========================================================================
// End-of-File
// ===========================================================================
