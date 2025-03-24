// ===========================================================================
// BigIntExamples.cpp
// ===========================================================================

#include "BigInt.hpp"

#include <format>
#include <iostream>
#include <print>
#include <string>

// ===========================================================================
// adding std::println support to class BigIng

namespace std {

    // formatter for class BigInt
    template <>
    struct std::formatter<BigInt> {
        constexpr auto parse(std::format_parse_context & ctx) {
            return ctx.begin();
        }

        auto format(const BigInt& big, std::format_context & ctx) const {
            std::string s = big.to_string();
            return std::format_to(ctx.out(), "{}", s);
        }
    };
}

// ===========================================================================
// adding Faculty support:
// 'BigFaculty' template can be used both for size_t and BigInt types


// function to find faculty of given number
static BigInt factorial(size_t n)
{
    BigInt res = 1;

    for (int i = 2; i <= n; i++)
        res *= i;
    
    return res;
}

//static BigInt factorial(size_t n)
//{
//    BigInt res = 1;
//
//    for (BigInt i = 2; i <= n; i++)
//        res *= i;
//
//    return res;
//}


//class BigFaculty
//{
//public:
//    template <typename T>
//    static T faculty(const T& n)
//    {
//        if (n == static_cast<T> (1))
//            return static_cast<T> (1);
//        else
//            return n * faculty(n - static_cast<T> (1));
//    }
//};

// ===========================================================================
// BigInt examples

namespace BigIntExamples {

    static void bigint_example_01() {

        BigInt n = 1234567890;
        std::cout << n << std::endl;
        std::println("{}", n);
    }

    static void bigint_example_02() {

        // testing addition
        BigInt n1{ "11111111" };
        BigInt n2{ "22222222" };
        std::println("{} + {} = {}", n1, n2, n1 + n2);

        n1 = BigInt{ "99999999999999" };
        n2 = BigInt{ "1" };
        std::cout << n1 << " + " << n2 << " = " << n1 + n2 << std::endl;
    }

    static void bigint_example_03_faculty() {

        // testing faculty
        for (size_t n = 2; n != 21; ++n)
        {
            BigInt f{ factorial(n) };
            std::cout << "Faculty of " << n << ": " << f << std::endl;
            //std::println("Faculty of {}: {}", n, f);
        }
    }

}

void big_int_examples()
{
    using namespace BigIntExamples;

    bigint_example_01();
    bigint_example_02();
    // bigint_example_03_faculty();
}

// ===========================================================================
// End-of-File
// ===========================================================================
