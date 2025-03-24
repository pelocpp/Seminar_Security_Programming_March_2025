// ===========================================================================
// SecureProgrammingIssues.cpp // Secure Programming
// Exploitability // Vulnerability
// ===========================================================================

// don't use the secure versions of the CRT library functions
#define _CRT_SECURE_NO_WARNINGS   // that's ugly

#include <complex>
#include <cstring>
#include <iostream>
#include <print>
#include <cstdio>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>

namespace SecureProgrammingExploitability {

    namespace UnsignedIntegerWraparound {

        static void test_assember_01() {

            short s1 = 10;
            short s2 = 11;

            short s3 = 0;

            s3 = s1 * s2;

            // ===============

            int i1 = 10;
            int i2 = 11;

            int i3 = 0;

            i3 = i1 * i2;

        }

        static void test_assember_02() {

            int start = 1;

            for (int i = 0; i < 10; ++i) {

                start = start * 2;
            }

            int result = start;
        }

        static void test_assember_03() {

            int n = 0;
            int i = 10;

            n = ++i;

            n = i++;  // hier muss eine Kopie von i gemerkt werden

            // Persönliche Empfehlung

            ++i;
            n = i;

            n = i;
            i++;

            // ============ 
            // Nebeneffekte in C/C++

            // Short-Circuit Evaluation:  && und ||

            // Was passiert, wenn die Bedingung "n > i" NICHT erfüllt ist

            // es wird ++i nicht ausgeführt // NIEMALS !!!
            if (n > i && i++ < 10) {

                // tue irgendwas
                printf("");
            }
        }

        int product(int x, int y, int z, int u, int v) {

            int result = x * y * z * u * v;
            return result;
        }

        static void test_assember_04() {

            int a = 5;
            int b = 6;
            int c = 7;
            int d = 8;
            int e = 9;

            int ergebnis = product(a, b, c, d, e);
        }

        static void test_unsigned_integer_wraparound() {

            // https://cwe.mitre.org/data/definitions/190.html

            // Unsigned Integer Wraparound
            // Defined behaviour: Wrapping

            {
                // wrap around - well defined behaviour
                unsigned int n = UINT_MAX - 1;
                printf("%u\n", n);

                n++;
                printf("%u\n", n);

                n++;    /* <- unsigned arithmetic, overflows, wraps around */
                printf("%u\n", n);

                n++;
                printf("%u\n", n);
            }

            {
                // undefined behavior
                unsigned short n = USHRT_MAX;
                printf("%hu\n", n);

                // n *= INT_MAX;
                n *= 12345;
                printf("%hu\n", n);
            }
        }
    }

    namespace SignedIntegerOverflow {

        // https://cwe.mitre.org/data/definitions/190.html

        // Signed Integer Overflow
        // Undefined behaviour: Overflow

        static const signed short first_len = SHRT_MAX;
        static const signed short second_len = 256;
        static const signed short buf_len = 256;

        static char first[first_len];
        static char buf[buf_len];

        static void test_signed_integer_overflow() {

            signed short len = first_len + second_len;  // <- UB: negative

            if (len <= 256) {
                memcpy(buf, first, first_len);
            }
        }
    }

    namespace NumericTruncationError {

        // https://cwe.mitre.org/data/definitions/197.html

        // Numeric Truncation Error
        // Implementation Defined Behaviour (IDB):
        // Integer Conversions do result in lost or misinterpreted data

        static void test_numeric_truncation_error_01()
        {
            int intPrimitive = 0;
            short shortPrimitive = 0;
            intPrimitive = INT_MAX;
            shortPrimitive = intPrimitive;   // Numeric Truncation Error

            printf("Integer MAXINT: %d\n", intPrimitive);
            printf("Short   MAXINT: %d\n", shortPrimitive);

            shortPrimitive = SHRT_MAX;
            printf("Short   MAXINT: %d\n", shortPrimitive);
        }

        static const unsigned short first_len = USHRT_MAX - 256;
        static const unsigned short second_len = 256;
        static const unsigned short buf_len = 256;

        static char first[first_len];
        static char buf[buf_len];

        static void test_numeric_truncation_error_02() {

            signed short len = first_len + second_len;  // <- IDB (negative) // unsigned sum is assigned to signed variable (!)

            if (len <= 256) {
                memcpy(buf, first, first_len);
            }
        }

        static void test_numeric_truncation_error() {

            test_numeric_truncation_error_01();
            test_numeric_truncation_error_02();
        }
    }

    namespace StackBasedBufferOverflow {

        // https://cwe.mitre.org/data/definitions/121.html
        // Stack-based Buffer Overflow
        
        // https://cwe.mitre.org/data/definitions/242.html
        // Use of Inherently Dangerous Function

        // https://cwe.mitre.org/data/definitions/787.html
        // Out-of-bounds Write

        static void test_stack_based_buffer_overflow_01() {

            const int Size = 32;
            char password[Size];
            // gets(password); // <- Write outside  // Deprecated in C++ 11 // Removed in C++ 14
        }

        static void test_stack_based_buffer_overflow_02() {

            const int Size = 32;
            char password[Size];
            std::println("Please enter Password: ");
            fgets(password, Size, stdin);

            auto result = strncmp(password, "12345", 5);
            if (result == 0) {
                std::println("Login successful!");
            }
        }

        static void corrupt_stack(const char* input) {

            char buffer[32];
            strcpy(buffer, input);
            std::println("{}", buffer);
        }

        static void test_stack_based_buffer_overflow_03() {

            corrupt_stack("This is way too long for this buffer");
        }

        static void call_myself(int tiefe) {

            int daten[50];

            tiefe++;

            call_myself(tiefe);
        }

        static void test_stack_based_buffer_overflow_04() {

            call_myself(1);
        }

        static void test_stack_based_buffer_overflow() {

            //test_stack_based_buffer_overflow_01();
            //test_stack_based_buffer_overflow_02();
            //test_stack_based_buffer_overflow_03();
           // test_stack_based_buffer_overflow_04();
        }
    }

    namespace HeapBasedBufferOverflow {

        // https://cwe.mitre.org/data/definitions/122.html
        // Heap-based Buffer Overflow

        static void test_heap_based_buffer_overflow_internal(const char* input) {

            char* buffer = new char[32];

            // Heap Buffer Overflow when data is bigger than 32
            strcpy(buffer, input);          // <- Write outside 
            std::println("{}", buffer);

            delete[] buffer;                // crashes due to outside write of 'strcpy'
        }

        static void test_heap_based_buffer_overflow() {

            test_heap_based_buffer_overflow_internal("This is way too long for this buffer");
        }

        static void test_heap_based_buffer_overflow_02() {

            //int* ip = (int*) malloc(32);

            //int nichtErnst1 = ip[-1];
            //int nichtErnst2 = ip[-2];
            //int nichtErnst3 = ip[-3];
            //int nichtErnst4 = ip[-4];

            //nichtErnst1 = -1[ip];

            //nichtErnst1 = *(ip - 1);

            //ip[-4] = 9999;

            //free(ip);

        }
    }

    namespace BufferUnderwriteUnderflow {

        // https://cwe.mitre.org/data/definitions/124.html
        // Buffer Underwrite Underflow

        static void test_buffer_underwrite_underflow () {

            char src[12] = { '?' };

            char src2[12];
            for (int i = 0; i < 12; ++i) {
                src2[i] = '?';
            }

            // std::fill  // STL // C++ // memset

            strncpy(src, "Hello World", sizeof(src));

            size_t length = strlen(src);

            int index = (length - 1);
            while (src[index] != ':') {
                src[index] = '\0';
                index--;
            }
        }

        static void test_buffer_underwrite_underflow_02() {

            int x = 10;
            int y = 11;

            int* adrX = &x;

            *(adrX + 4) = 123;
        }
    }

    namespace UseAfterFree {

        // https://cwe.mitre.org/data/definitions/416.html
        // Use After Free
        // Don't access freed memory

        static void test_use_after_free() {

            char stackBuffer [32];

            char* buffer = new char[32];
            memset(buffer, '!', 32);

            bool error = true;
            if (error)
                delete[] buffer;

            //if (error) {
            //    // Use after free when error is true
            //    printf("%lu\n", strlen(buffer));

            //    size_t len = strlen(buffer);   // use after free
            //}
        }
    }

    namespace DoubleFree {

        // https://cwe.mitre.org/data/definitions/415.html
        // Double Free
        // Properly deallocate dynamically allocated resources

        static void test_double_free() {

            {
                char* buffer = NULL;

                delete buffer;  // auch free geht bei NULL !!!
            }

            char* buffer = new char[256];
            memset(buffer, '!', 256);

            bool error = true;
            if (error)
                delete[] buffer;

            // ....

            //delete[] buffer; // second free
        }
    }

    namespace IncorrectTypeConversion {

        // https://cwe.mitre.org/data/definitions/704.html
        // Do not cast to an unrelated type

        static void test_incorrect_type_conversion_01() {

            struct A {};
            struct B {};

            struct A* a = (struct A*)malloc(sizeof(struct A));

            // C-Style cast to unrelated type: No - Go
            struct B* b = (struct B*) a;
        }

        static void test_incorrect_type_conversion_02() {

            uint16_t data{ 0x1234 };

            uint16_t* u16 = &data;

            uint32_t* u32 = (uint32_t*) &data;

       //     *u32 = 0x12345678; // de-referencing invokes undefined behavior

            printf("%hx\n", data);
            printf("%hx\n", *u16);
            printf("%x\n", *u32);
        }

        static void test_incorrect_type_conversion() {

            test_incorrect_type_conversion_01();
            test_incorrect_type_conversion_02();
        }
    }

    namespace UseOfExternalFormatString {

        // https://cwe.mitre.org/data/definitions/134.html
        // Use of Externally-Controlled Format String
        // Only use valid format strings

        static void test_use_of_external_format_string_internal(const char* format, const char* str) {

            // Überprüfung bzgl. Parameter format

            printf(format, str);   // Uhhhhhhhhhhhhhhhhhhhhhhhh
        }

        static void test_use_of_external_format_string() {

            test_use_of_external_format_string_internal("%s", "Very, very long string");

        //    test_use_of_external_format_string_internal("%s %d", "Very, very long string");
        }
    }
}

// ===========================================================================

void secure_programming_issues()
{
    using namespace SecureProgrammingExploitability;

    UnsignedIntegerWraparound::test_assember_01();
    UnsignedIntegerWraparound::test_assember_02();
    UnsignedIntegerWraparound::test_assember_03();
    UnsignedIntegerWraparound::test_assember_04();

    //UnsignedIntegerWraparound::test_unsigned_integer_wraparound();
    //SignedIntegerOverflow::test_signed_integer_overflow();
    //NumericTruncationError::test_numeric_truncation_error();
    //StackBasedBufferOverflow::test_stack_based_buffer_overflow();
    //HeapBasedBufferOverflow::test_heap_based_buffer_overflow_02();
    //HeapBasedBufferOverflow::test_heap_based_buffer_overflow();
    // BufferUnderwriteUnderflow::test_buffer_underwrite_underflow();
    BufferUnderwriteUnderflow::test_buffer_underwrite_underflow_02();
    UseAfterFree::test_use_after_free();
    DoubleFree::test_double_free();
    IncorrectTypeConversion::test_incorrect_type_conversion();
    UseOfExternalFormatString::test_use_of_external_format_string();
}

// ===========================================================================
// End-of-File
// ===========================================================================
