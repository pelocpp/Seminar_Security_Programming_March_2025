// ===========================================================================
// Guidelines_GenericProgramming.cpp
// ===========================================================================

#include <print>

namespace GuidelinesGenericProgramming {

    // =======================================================================
    // Level of Abstraction

    bool isGreaterThanFifty(int n) {

        return n > 50;
    }

    template <typename T>
    bool isGreaterThanFifty(T n) {

        return n > T{ 50 };
    }

    //bool isGreaterThanFifty(auto n) {
    //
    //    return n > decltype(n) { 50 };
    //}

    // =======================================================================
    // Level of Abstraction

    template <typename T>
    class Point2D
    {
    public:
        Point2D(T x, T y) : m_x{ x }, m_y{ y } {}

        auto x() { return m_x; }
        auto y() { return m_y; }
        // ...

    private:
        T m_x{};
        T m_y{};
    };
}

void guidelines_generic_programming()
{
    using namespace GuidelinesGenericProgramming;

    bool b1{ isGreaterThanFifty(100) };

    bool b2{ isGreaterThanFifty(123.456) };

    bool b3{ isGreaterThanFifty(123ll) };
}

// ===========================================================================
// End-of-File
// ===========================================================================
