// ===========================================================================
// Guidelines_STL_Algorithms.cpp
// ===========================================================================

//#include <cassert>
#include <algorithm>
#include <map>
#include <print>
#include <vector>
#include <ranges>

namespace GuidelinesSTLAlgorithms {

    // =======================================================================
    // Copy

    class Employee
    {
    private:
        std::string   m_name;
        size_t        m_age;
        size_t        m_id;
        unsigned int  m_salary;
    
    public:
        Employee() = default;
        Employee(const std::string& name, size_t age, size_t id, unsigned int salary) 
            : m_name{ name }, m_age{ age }, m_id{ id }, m_salary{ salary }
        {}

        std::string uniqueName() const { return m_name; }
        unsigned int salary() const { return m_salary; }
        bool isManager() const { return false; }
    };

    namespace STLAlgorithms_Copy {

        static void guidelines_stl_algorithms_copy_01() {

            std::vector<Employee> source;
            //...

            std::vector<Employee> employees;
            employees.reserve(source.size());

            // using for loop
            for (auto const& employee : source) {
                employees.push_back(employee);
            }
        }

        static void guidelines_stl_algorithms_copy_02() {

            std::vector<Employee> source;
            //...

            std::vector<Employee> employees;
            employees.reserve(source.size());

            // using STL algorithm 'std::copy'
            std::copy(
                source.begin(),
                source.end(),
                std::back_inserter(employees)
            );
        }

        static void guidelines_stl_algorithms_copy_03() {

            std::vector<Employee> source;
            //...

            // using appropriate container constructor
            std::vector<Employee> employees (source.begin(), source.end());
        }

        static void guidelines_stl_algorithms_copy() {

            guidelines_stl_algorithms_copy_01();
            guidelines_stl_algorithms_copy_02();
            guidelines_stl_algorithms_copy_03();
        }
    }

    // =======================================================================
    // Transform

    namespace STLAlgorithms_Transform {

        static void guidelines_stl_algorithms_transform_01() {

            std::vector<Employee> employees;
            //...

            std::map<std::string, unsigned int> salariesByName;

            // for loop
            for (auto const& employee : employees) {
                salariesByName[employee.uniqueName()] = employee.salary();
            }

            // or
            for (auto const& employee : employees) {
                salariesByName.insert(
                    std::make_pair(employee.uniqueName(), employee.salary())
                );
            }
        }

        static void guidelines_stl_algorithms_transform_02() {

            std::vector<Employee> employees;
            //...

            std::map<std::string, unsigned int> salariesByName;

            // using STL algorithm
            std::transform(
                employees.begin(),
                employees.end(),
                std::inserter(salariesByName, salariesByName.end()),
                [](auto const& employee) {
                    return std::make_pair(
                        employee.uniqueName(),
                        employee.salary()
                    );
                }
            );
        }

        static void guidelines_stl_algorithms_transform_03() {

            std::vector<Employee> employees;
            //...

            std::map<std::string, unsigned> salariesByName;

            for (auto const& employee : employees) {
                if (!employee.isManager()) {
                    salariesByName[employee.uniqueName()] = employee.salary();
                }
            }
        }

        template <typename InIter, typename OutIter, typename UnaryOp, typename Pred>
        OutIter transform_if(InIter first, InIter last,
            OutIter result, UnaryOp unaryOp, Pred pred) {
            for (; first != last; ++first) {
                if (pred(*first)) {
                    *result = unaryOp(*first);
                    ++result;
                }
            }
            return result;
        }

        static void guidelines_stl_algorithms_transform_04() {

            std::vector<Employee> employees;

            std::map<std::string, unsigned int> salariesByName;

            // using STL algorithm
            transform_if(
                employees.begin(),
                employees.end(),
                std::inserter(salariesByName, salariesByName.end()),
                [](auto const& employee) {
                    return std::make_pair(
                        employee.uniqueName(),
                        employee.salary()
                    );
                },
                [](auto const& employee) {
                    return !employee.isManager();
                }
            );
        }

        static void guidelines_stl_algorithms_transform() {

            guidelines_stl_algorithms_transform_01();
            guidelines_stl_algorithms_transform_02();
            guidelines_stl_algorithms_transform_03();
        }
    }

    // =======================================================================
    // Copy and Transform with Ranges

    namespace STLAlgorithms_Copy_and_Transform_with_Ranges {

        // https://arne-mertz.de/2019/05/algorithms-and-the-kiss-principle/

        static void guidelines_stl_algorithms_copy_ranges() {

            std::vector<Employee> source;
            //...

            auto employees = source | std::ranges::to<std::vector>();

            // using for loop
            for (auto const& employee : source) {
                employees.push_back(employee);
            }
        }

        static void guidelines_stl_algorithms_transform_ranges() {

            std::vector<Employee> employees;
            //...

            auto salariesByName = employees

                | std::views::filter([](auto const& employee) {
                return !employee.isManager();
                    })

                | std::views::transform([](auto const& employee) {
                return std::make_pair(
                    employee.uniqueName(),
                    employee.salary()
                );
                    })

                | std::ranges::to<std::map>();
        }

        static void guidelines_stl_algorithms_with_ranges() {

            guidelines_stl_algorithms_copy_ranges();
            guidelines_stl_algorithms_transform_ranges();
        }
    }

    // =======================================================================
    // Copy and Transform Benchmarks

    namespace STLAlgorithms_Copy_and_Transform_Benchmark {

        static void guidelines_stl_algorithms_copy_benchmark_01() {

            std::vector<Employee> source
            {
                { "Hans", 30, 334455, 2500 },
                { "Hans", 30, 334455, 2700 },
                { "Hans", 30, 334455, 2000 },
                { "Hans", 30, 334455, 3500 },
                { "Hans", 30, 334455, 3000 }
            };
            
            std::vector<Employee> employees;
            employees.reserve(source.size());

            // using for loop
            for (auto const& employee : source) {
                employees.push_back(employee);
            }
        }

        static void guidelines_stl_algorithms_copy_benchmark_02() {

            std::vector<Employee> source
            {
                { "Hans", 30, 334455, 2500 },
                { "Hans", 30, 334455, 2700 },
                { "Hans", 30, 334455, 2000 },
                { "Hans", 30, 334455, 3500 },
                { "Hans", 30, 334455, 3000 }
            };

            std::vector<Employee> employees;
            employees.reserve(source.size());

            // using STL algorithm 'std::copy'
            std::copy(
                source.begin(),
                source.end(),
                std::back_inserter(employees)
            );
        }
    }
}

void guidelines_stl_algorithms()
{
    using namespace GuidelinesSTLAlgorithms;

    STLAlgorithms_Copy::guidelines_stl_algorithms_copy();
    STLAlgorithms_Transform::guidelines_stl_algorithms_transform();
    STLAlgorithms_Copy_and_Transform_with_Ranges::guidelines_stl_algorithms_with_ranges();
}

// ===========================================================================
// End-of-File
// ===========================================================================
