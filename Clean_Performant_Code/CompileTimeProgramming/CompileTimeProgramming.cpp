// ===========================================================================
// CompileTimeProgramming.cpp
// ===========================================================================

#include <iostream>
#include <print>

namespace MetaprogrammingWithTemplates {

    // =======================================================================
    // Metaprogramming with Templates: Function Template

    template <typename T>
    auto powerN(const T& v, size_t n) {
        auto product = T{ 1 };
        for (size_t i{}; i != n; ++i) {
            product *= v;
        }
        return product;
    }

    static void metaprogramming_01()
    {
        auto x{ powerN<float>(1.5f, 3) };   // x is a float
        auto y{ powerN<int>(3, 4) };        // y is an int

        std::println("powerN: {}", x);
        std::println("powerN: {}", y);
    }

    static void metaprogramming_02()
    {
        auto x{ powerN(2.5, 5) };           // x is a float
        auto y{ powerN(3, 6) };             // y is an int

        std::println("powerN: {}", x);
        std::println("powerN: {}", y);
    }

    // =======================================================================
    // Metaprogramming with Templates: Class Template

    template <typename T>
    class Rectangle
    {
    private:
        T m_x{};
        T m_y{};
        T m_width{};
        T m_height{};

    public:
        Rectangle(T x, T y, T width, T height)
            : m_x{ x }, m_y{ y }, m_width{ width }, m_height{ height }
        {
        }

        auto getX() const { return m_x; }
        auto getY() const { return m_y; }
        auto width() const { return m_width; }
        auto height() const { return m_height; }
        auto area() const { return m_width * m_height; }
        auto circumference() const { return 2 * (m_width * m_height); }
    };
}

namespace std
{
    // =======================================================================
    // std::println

    using namespace MetaprogrammingWithTemplates;

    template <typename T>
    struct formatter<Rectangle<T>>
    {
        constexpr auto parse(std::format_parse_context& ctx) {
            return ctx.begin();
        }

        auto format(const Rectangle<T>& rect, std::format_context& ctx) const {

            auto x{ rect.getX() };
            auto y{ rect.getY() };
            auto width{ rect.width() };
            auto height{ rect.height() };

            return std::format_to(
                ctx.out(),
                "Rectangle at {}:{} [width: {} / height: {}]",
                x, y, width, height
            );
        }
    };
}

namespace MetaprogrammingWithTemplates {

    // =======================================================================
    // Function Template accepting a Class Template 

    template <typename T>
    auto isSquare(const Rectangle<T>& rect) {
        return rect.width() == rect.height();
    }

    static void metaprogramming_03()
    {
        auto r1{ Rectangle<float>{ 1.0f, 2.0f, 3.0f, 4.0f } };
        auto r2{ Rectangle{ -2, -2, 4, 4 } };

        std::println("{}", r1);
        std::println("{}", r2);

        auto b1{ isSquare(r1) };
        auto b2{ isSquare(r2) };

        std::println("isSquare: {}", b1);
        std::println("isSquare: {}", b2);
    }
}

namespace MetaprogrammingWithTemplates {

    // =======================================================================
    // Using integers as template parameters and
    // providing specializations of a template

    template <int N, typename T>
    auto morePowerN(const T& v) {
        auto product = T{ 1 };
        for (size_t i{}; i != N; ++i) {
            product *= v;
        }
        return product;
    }

    // (explicit) template specialization 
    template<>
    auto morePowerN<2, int>(const int& v) {
        return v * v;
    }

    static void metaprogramming_04()
    {
        auto x1{ morePowerN<2>(4) };
        auto x2{ morePowerN<3>(4) };

        std::println("{}", x1);
        std::println("{}", x2);

        auto x3 { morePowerN<3,double>(4.5) };
        auto x4 { morePowerN<3,float>(4.5) };

        std::println("{}", x3);
        std::println("{}", x4);

        auto x5{ morePowerN<2>(4) };
        std::println("{}", x5);
    }
}

namespace MetaprogrammingWithTemplates {

    // =======================================================================
    // Abbreviated Function Templates Syntax

    static auto anotherPowerN(const auto& v, int n) {
        auto product = decltype(v){ 1 };
        for (size_t i{}; i != n; ++i) {
            product *= v;
        }
        return product;
    }

    static void metaprogramming_05()
    {
        auto x{ anotherPowerN<float>(1.5f, 3) };   // x is a float
        auto y{ anotherPowerN<int>(3, 4) };        // y is an int

        std::println("powerN: {}", x);
        std::println("powerN: {}", y);
    }
}

namespace MetaprogrammingWithTemplates {

    // =======================================================================
    // Programming with constant expressions and functions
    // constexpr vs consteval

    static constexpr auto sum(int x, int y, int z) { return x + y + z; }

    static consteval auto sub(int x, int y, int z) { return x - y - z; }

    static void metaprogramming_06()
    {
        constexpr auto value1 = 1 + 2 + 3;          // constant expression

        constexpr auto value2 = sum(1, 2, 3);       //  value2 is constexpr

        constexpr auto value3 = sub(5, 1, 1);       //  value3 is constexpr

        auto value4 = sum(1, 2, 3);                 //  value4 is not constexpr

        auto value5 = sub(5, 1, 1);                 //  value5 is not constexpr
    }

    static void metaprogramming_07()
    {
        int x, y, z;

        std::cin >> x >> y >> z;                    // get user input
        
        auto value1 = sum(x, y, z);

        // auto value2 = sub(x, y, z);              // error: call to immediate function is not a constant expression
    }
}

// =================================================================

void compile_time_programming()
{
    using namespace MetaprogrammingWithTemplates;

    metaprogramming_01();
    metaprogramming_02();
    metaprogramming_03();
    metaprogramming_04();
    metaprogramming_05();
    metaprogramming_06();
    // metaprogramming_07();  // needs user input
}

// ===========================================================================
// End-of-File
// ===========================================================================
