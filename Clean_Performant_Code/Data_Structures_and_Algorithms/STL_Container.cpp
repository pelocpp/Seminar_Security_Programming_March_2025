// ===========================================================================
// STL_Container.cpp
// ===========================================================================

#include <array>
#include <map>
#include <print>
#include <queue>
#include <span>
#include <stack>
#include <string>
#include <vector>

namespace STLContainer {

    namespace Vectors {

        static void test_vector()
        {
            {
                auto vec = std::vector{ 1, 2, 3 };

                vec.push_back(4);
                vec.push_back(5);

                std::println("Size: {} - Capacity: {}", vec.size(), vec.capacity());
            }

            {
                auto vec = std::vector{ 1, 2, 3, 4, 5 };
                for (auto elem : vec) {
                    std::print("{} ", elem);
                }
                std::println();
            }

            {
                auto vec = std::vector{ -1, 5, 2, -3, 4, -5, 5 };

                std::erase(vec, 5);                                 // v: [-1, 2, -3, 4, -5]
                for (auto elem : vec) {
                    std::print("{} ", elem);
                }
                std::println();

                std::erase_if(vec, [] (auto x) { return x < 0; });  // v: [2, 4]
                for (auto elem : vec) {
                    std::print("{} ", elem);
                }
                std::println();
            }
        }

        static auto print(const std::array<int, 10>& a) {

            for (auto elem : a) {
                std::print("{} ", elem);
            }
        }

        static void test_std_array()
        {
            {
                auto a = std::array<int, 5>{ 1, 2, 3, 4, 5 };

                auto b = std::array{ 1, 2, 3, 4, 5 };
            }

            {
                auto a = std::array<int, 5>{ 1, 2, 3, 4, 5 };

                for (auto elem : a) {
                    std::print("{} ", elem);
                }
            }

            {
                auto a = std::array<int, 10>{};
                auto b = std::array<int, 20>{};

                print(a);
                // print(b); // does not compile, print requires an int array of size 10
            }
        }
    }

    namespace Stacks {

        static void test_stack()
        {
            std::stack<int> s;

            s.push(1);
            s.push(2);
            s.push(3);
            s.push(4);
            s.push(5);

            std::println("Size of stack: {} ", s.size());
            std::println("Elements:");

            while (!s.empty()) {
                std::print("{} ", s.top());
                s.pop();
            }
        }
    }

    namespace Queues {

        static void test_queue()
        {
            std::queue<int> q;

            q.push(1);
            q.push(2);
            q.push(3);
            q.push(4);
            q.push(5);

            std::println("Size of queue: {} ", q.size());
            std::println("Elements:");

            while (! q.empty()) {
                std::print("{} ", q.front());
                q.pop();
            }
        }
    }

    namespace PriorityQueues {

        static void test_priority_queue()
        {
            std::priority_queue<int> pq;

            pq.push(3);
            pq.push(1);
            pq.push(2);
            pq.push(5);
            pq.push(4);

            std::println("Size of priority queue: {} ", pq.size());
            std::println("Elements:");

            while (! pq.empty()) {
                std::print("{} ", pq.top());
                pq.pop();
            }
        }
    }

    namespace FlatMap {

        static void test_flat_map() {

            std::map<std::string, int> people;   // replace 'std::map' with 'flat_map', add "#include <flat_map>"

            people["Alice"] = 25;
            people["Bob"] = 30;
            people["Carol"] = 35;

            for (const std::pair<std::string, int>& pair : people) {
                std::println("{} is {} years old.", pair.first, pair.second);
            }

            int aliceAge{ people["Alice"] };
            std::println("Alice is {} years old.", aliceAge);

            people.erase("Alice");

            bool aliceExists{ people.contains("Alice") };
            std::println("Alice exists in the flat_map: {}.", aliceExists);
        }
    }

    namespace Span {

        //static void func1(double buffer[]) {
        //    const auto n = std::size(buffer);   // does not compile!
        //    
        //    for (auto i = 0u; i < n; ++i) {     // size is lost!
        //        std::println("{}: {}.", i, buffer[i]);
        //    }
        //}

        static void func(double buffer[], size_t n) {

            for (auto i = 0u; i < n; ++i) {                // using classic for-loop - indices necessary
                std::println("{}: {}.", i, buffer[i]);
            }
        }

        static void test_array() {

            double a[5] = { 1.5, 2.5, 3.5 , 4.5 , 5.5 };

            func(a, 5);                              // smells (length 5 is explicitly used)
            func(a, sizeof(a) / sizeof(a[0]));       // correct, but a tedious pattern
            func(a, std::size(a));                   // better
        }

        static void funcSpan(std::span<double> buffer) {       // Pass by value - one single parameter

            for (auto elem : buffer) {                         // Range-based for-loop
                std::print("{} ", elem);
            }
            std::println();
        }

        static void test_span() {

            double a[5] { 1.5, 2.5, 3.5 , 4.5 , 5.5 };
            auto arr = std::array{ 6.5, 7.5, 8.5 , 9.5 , 10.5 };
            auto vec = std::vector{ 1.1, 2.2, 3.3, 4.4, 5.5 };

            std::span sp{ a };       // constructs span from array
            funcSpan(sp);
            // or shorter
            funcSpan(a);

            std::span spa{ arr };    // constructs span from std::array
            funcSpan(spa);
            // or shorter
            funcSpan(arr);

            std::span spv{ vec };    // constructs span from std::vector
            funcSpan(spv);
            // or shorter
            funcSpan(vec);
        }
    }
}

// =================================================================

void test_stl_container()
{
    using namespace STLContainer::Vectors;
    test_vector();
    test_std_array();

    using namespace STLContainer::Stacks;
    test_stack();

    using namespace STLContainer::Queues;
    test_queue();

    using namespace STLContainer::PriorityQueues;
    test_priority_queue();

    using namespace STLContainer::FlatMap;
    test_flat_map();

    using namespace STLContainer::Span;
    test_array();
    test_span();
}

// ===========================================================================
// End-of-File
// ===========================================================================
