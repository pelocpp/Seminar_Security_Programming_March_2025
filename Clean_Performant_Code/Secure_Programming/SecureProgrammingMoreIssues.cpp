// ===========================================================================
// SecureProgrammingMoreIssues.cpp
// More Issues 
// ===========================================================================

// don't use the secure versions of the CRT library functions
#define _CRT_SECURE_NO_WARNINGS 

#include <atomic>
#include <cstring>
#include <iostream>
#include <print>
#include <thread>
#include <vector>

namespace MemoryLeaks {

    static void test_memory_leaks()
    {
        int* ptr = new int[10]; // memory allocated but never deallocated
    }

    static void test_static_third_example()
    {
        static int value = 123;

        static int value2[1000] = { 1,2 ,3};

        value++;
    }
}

namespace SecureProgrammingMoreIssues {

    namespace UsingPointers {

        struct Numbers
        {
            int m_numbers[1000];
        };

        static void func(int* ptr) {
            ptr[0] = 123;
        }

        // Call by Value
        static void func2(struct Numbers numbers) {

            size_t s = sizeof(numbers);
            s = sizeof(struct Numbers);
            numbers.m_numbers[0] = 123;
        }

        // call-by-value oder call-by-address
        // Von Fall zu Fall zu überlegen:
        // call-by-value: Schützt das Original
        // call-by-address: PERFORMANZ!!! m ggf. mit const kombinieren
        static void func3(/*const*/ struct Numbers* pNumbers) {

            size_t s = sizeof(pNumbers);
            s = sizeof(struct Numbers);
            (*pNumbers).m_numbers[0] = 123;
            // oder etwas geschmeidiger
            pNumbers->m_numbers[0] = 123;
        }

        // Haben wir es bei call-by-reference mit Kopie oder Adresse zu tun:
        // Es ist hinter den Kulissen eine Adresse
        static void func4(/*const*/ struct Numbers& pNumbers) {

            size_t s = sizeof(pNumbers);
            s = sizeof(struct Numbers);
            pNumbers.m_numbers[0] = 123;
        }

        void testCallingConventions()
        {
            int numbers[1000] = {};
            func(numbers);

            struct Numbers num = {};
            func2(num);

            func3(&num);
        }


        static void decay(const int* ages) {
            // Size of the pointer = 8
            std::println("Size of an 'int*' pointer:          {}", sizeof(ages));

            // Compile Error
            // std::cout << std::size(ages) << '\n';
        }



        static void decay2(const int* ages) {
            // Size of the pointer = 8
            std::println("Size of an 'int*' pointer:          {}", sizeof(ages));

            // Compile Error
            // std::cout << std::size(ages) << '\n';
        }

        static void decay2(const int* ages, int len) {
            // Size of the pointer = 8
            std::println("Size of an 'int*' pointer:          {}", sizeof(ages));

            // Compile Error
            // std::cout << std::size(ages) << '\n';
        }

        static void test_using_pointers_demstrating_decay() {

            int ages[3] = { 15, 30, 50 };
            // Number of elements = 3
            std::println("Number of array elements:           {}", std::size(ages));

            // Size of an element = 4
            std::println("Size of a single array element:     {}", sizeof(ages[0]));

            // Size of array = 12 (= 3 * 4)
            std::println("Number of bytes used by this array: {}", sizeof(ages));
           // decay(ages);
            decay2(ages, sizeof(ages) / sizeof(ages[0]));
        }

        static void test_using_pointers_std_size() {

            std::vector<int> numbers{ 1, 2, 3 };
            std::println("Number of std::vector elements:           {}", std::size(numbers));

            numbers.push_back(4);
            numbers.push_back(5);
            numbers.push_back(6);

            std::println("Number of std::vector elements:           {}", std::size(numbers));
        }

        static void test_using_pointers() {

            test_using_pointers_demstrating_decay();
            test_using_pointers_std_size();
        }
    }

    namespace DanglingReferences {

        struct MyStruct{
            int n;
        };

        static void test_function() {

            int n = 123;

            int& rn = n;

            int* ip = NULL;

            // Heap oder kein Heap

            struct MyStruct* sp = new MyStruct();

            sp->n = 123;

            struct MyStruct& name = *sp;

            name.n = 123;

            delete sp;

            int x = name.n;
        }

        struct Data
        {
            Data(int& value) : m_value(value) {}
            int& m_value;
        };

        static Data function() {

            int value = 123;

            Data data(value);

            std::println("value: {}", value);

            return data;                         // implicitly returning reference to local value
        }

        static void test_dangling_reference()
        {
            Data data = function();
            std::println("{}", data.m_value);    // Oooooops
        }
    }

    namespace MemsetIssue {

        // https://cwe.mitre.org/data/definitions/14.html

        // Compiler Removal of Code to Clear Buffers

        static bool connectToServer(char* pwd) {
            std::println("{}", pwd);
            return true;
        }

        static bool getPasswordFromUser(char* pwd, size_t pwdSize) {
            strncpy(pwd, "My super secret password", pwdSize);
            std::println("{}", pwd);
            return true;
        }

        static void test_disappearing_memset()
        {
            char pwd[64];

            if (getPasswordFromUser(pwd, sizeof(pwd))) {
                if (connectToServer(pwd)) {
                    // interaction with server
                }
            }

            std::memset(pwd, 0, sizeof(pwd)); // <- Removed by the optimizer !!!
        }
    }



    namespace RaceConditions {

        const int MaxCount = 1'000;

        long counter = 0;

        std::atomic<long> atomicCounter{};

        static void increment() {

            for (int i = 0; i != MaxCount; ++i) {
                ++counter;
            }
        }



        static void incrementAtomic() {

            for (int i = 0; i != MaxCount; ++i) {
                ++atomicCounter;
            }
        }

        static void test_race_conditions_unsafe()
        {
            std::println("Counter: {}", counter);

            std::thread t1{ increment };
            std::thread t2{ increment };

            t1.join();
            t2.join();

            std::println("Counter: {}", counter); // expected 200000, but result is non-deterministic
        }

        static void test_race_conditions_safe()
        {
            std::println("Counter: {}", atomicCounter.load());

            std::thread t1{ incrementAtomic };
            std::thread t2{ incrementAtomic };

            t1.join();
            t2.join();

            std::println("Counter: {}", atomicCounter.load());
        }

        static void test_race_conditions()
        {
            test_race_conditions_unsafe();
        //    test_race_conditions_safe();
        }
    }
}

// =================================================================

void secure_programming_more_issues()
{
    using namespace SecureProgrammingMoreIssues;

    //UsingPointers::testCallingConventions();
    //DanglingReferences::test_function();

    //UsingPointers::test_using_pointers();
    //DanglingReferences::test_dangling_reference();
    //MemsetIssue::test_disappearing_memset();
    //MemoryLeaks::test_memory_leaks();
    RaceConditions::test_race_conditions();
}

// ===========================================================================
// End-of-File
// ===========================================================================
