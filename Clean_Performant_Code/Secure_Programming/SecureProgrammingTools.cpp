// ===========================================================================
// SecureProgrammingTools.cpp
// Tools for Secure Programming
// ===========================================================================

#include <complex>
#include <print>

namespace SecureProgrammingTools {

    static int x[100];

    namespace UsingAddressSanitizer {

        static void test_valid_address_with_sanitizer() {

            std::println("Hello!");
            x[100] = 5; // Boom!
            std::println("Boom!");
        }

        // ---------------------

        std::complex<float> delta;
        std::complex<float> mc[4];

        static void test_infinite_loop_with_sanitizer() {

            for (int di = 0; di < 4; di++, delta = mc[di]) {

                std::println("{}", di);
            }
        }

        static void test_sanitizer()
        {
            test_valid_address_with_sanitizer();
            test_infinite_loop_with_sanitizer();
        }
    }

    namespace UsingClangTidy{

        static void test_clang_tidy()
        {
            int numbers[10];
        }
    }
}

// ===========================================================================

void secure_programming_tools()
{
    using namespace SecureProgrammingTools;

    UsingAddressSanitizer::test_sanitizer();
    UsingClangTidy::test_clang_tidy();
}

// ===========================================================================
// End-of-File
// ===========================================================================
