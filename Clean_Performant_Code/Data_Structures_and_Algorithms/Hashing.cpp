// ===========================================================================
// Hashing.cpp
// ===========================================================================

#include <print>
#include <string>
#include <unordered_map>

namespace DataStructuresAndAlgorithms {

    namespace Hashing {

        // =======================================================================
        // Hashing

        struct Person
        {
            std::string m_firstName;
            std::string m_lastName;
            size_t      m_age;

            bool operator== (const Person& other) const {

                return
                    m_firstName == other.m_firstName &&
                    m_lastName == other.m_lastName &&
                    m_age == other.m_age;
            }
        };
    }
}

namespace std
{
    // =======================================================================
    // std::hash

    using namespace DataStructuresAndAlgorithms::Hashing;

    template <>
    struct hash<Person>
    {
        size_t operator()(const Person& p) const {

            auto hash1{ std::hash<std::string>() (p.m_firstName) };
            auto hash2{ std::hash<size_t>() (p.m_age) };
            auto hash3{ std::hash<std::string>() (p.m_lastName) };

            size_t hash{ hash1 ^ (hash2 << 1) ^ (hash3 << 2) };  // combine these hash values
            return hash;
        }
    };
}

namespace std
{
    // =======================================================================
    // std::println

    using namespace DataStructuresAndAlgorithms::Hashing;

    template <>
    struct formatter<Person>
    {
        constexpr auto parse(std::format_parse_context& ctx) {
            return ctx.begin();
        }

        auto format(const Person& person, std::format_context& ctx) const {

            auto firstName{ person.m_firstName };
            auto lastName{ person.m_lastName };
            auto age{ person.m_age };

            return std::format_to(
                ctx.out(),
                "Person {} {} [Age: {}]",
                firstName, lastName, age
            );
        }
    };
}

namespace DataStructuresAndAlgorithms {

    namespace Hashing {

        // =======================================================================
        // Use Cases

        static void test_hashing_01()
        {
            std::unordered_map<Person, size_t> phoneBook;

            Person sepp = { "Sepp", "Meier", 30 };
            phoneBook[sepp] = 123456;

            // retrieving phone number of sepp
            auto phone{ phoneBook[sepp] };
            std::println("{} - Phone Number: {}", sepp, phone);
        }

        static void test_hashing_02()
        {
            std::unordered_map<Person, std::string> personJobs;

            Person sepp = { "Sepp", "Meier", 30 };
            personJobs[sepp] = "Entwickler";

            // retrieving job description of sepp
            auto job{ personJobs[sepp] };
            std::println("{} - Job: {}", sepp, job);
        }
    }
}

// =================================================================

void test_hashing()
{
    using namespace DataStructuresAndAlgorithms::Hashing;
    test_hashing_01();
    test_hashing_02();
}

// ===========================================================================
// End-of-File
// ===========================================================================
