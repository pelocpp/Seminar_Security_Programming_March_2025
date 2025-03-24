// ===========================================================================
// BestPractices.cpp
// ===========================================================================

#include <algorithm>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace PerformanceBestPractices {

    // =======================================================================
    // Avoid Unnecessary Copying

    static std::string prefix(const std::string& str) {
        if (str.length() >= 5) {
            // extract a part of string
            auto substr = str.substr(1, 4);
            // substr is a std::string
            // ...
            return substr;
        }
        return {};
    }

    static std::string_view prefix(std::string_view str) {
        if (str.length() >= 5) {
            // extract a part of string
            auto substr = str.substr(1, 4);
            // substr is a std::string_view
            // ...
            return substr;
        }
        return {};
    }

    static void best_practices_01_avoid_unnecessary_copying()
    {
        std::string s1{ "1234567890" };
        auto p1{ prefix(s1) };

        std::string_view s2{ "1234567890" };
        auto p2{ prefix(s2) };
    }

    // =======================================================================
    // Prefer Stack Allocation

    static int best_practices_02_prefer_stack_allocation()
    {
        int value = 123;          // stack allocation
        // ...
        return 0;                 // automatically deallocated
    }

    // =======================================================================
    // Optimize Loops

    static void best_practices_03_optimize_loops()
    {
        std::vector<int> numbers{ 1, 2, 3, 4, 5 };

        int sum{};
        for (const int& num : numbers) {
            sum += num;
        }
    }

    // =======================================================================
    // Reduce Function Calls

    inline static int square(int x) {
        return x * x;
    }

    static void best_practices_04_reduce_function_calls()
    {
        int result{ square(5) }; // inlined function
    }
}

// =======================================================================
// *Raw*-Wiederholungschleifen

static void processMoreData(const std::vector<int>& data) {}

static void processData(const std::vector<int>& data)
{
    bool inRange{ true };

    for (const auto& elem : data) {
        if (elem < 50 || elem > 100) {
            inRange = false;
            break;
        }
    }

    if (inRange) {
        processMoreData(data);
    }
}

static void processDataEx(const std::vector<int>& data)
{
    auto inRange = [](int value) { 
        return value < 50 || value > 100;
    };

    const bool allInRange{ std::all_of(data.begin(), data.end(), inRange) };

    if (allInRange) {
        processMoreData(data);
    }
}

static void best_practices_0x_raw_loops()
{
    std::vector<int> data = { 50, 70, 40, 80, 90 };

    processData(data);
    processDataEx(data);
}

// =================================================================

void performance_best_practices()
{
    using namespace PerformanceBestPractices;

    //best_practices_01_avoid_unnecessary_copying();
    //best_practices_02_prefer_stack_allocation();
    //best_practices_03_optimize_loops();
    //best_practices_04_reduce_function_calls();

    best_practices_0x_raw_loops();
}

// ===========================================================================
// End-of-File
// ===========================================================================
