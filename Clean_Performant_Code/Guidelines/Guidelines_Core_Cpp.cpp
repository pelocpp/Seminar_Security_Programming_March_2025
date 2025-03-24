// ===========================================================================
// Guidelines_Core_Cpp.cpp
// ===========================================================================

#include <cassert>
#include <fstream>
#include <iostream>
#include <map>
#include <print>

namespace GuidelinesCoreCpp {

    namespace CoreGuidelines {

        // =======================================================================
        // Invariants

        // https://www.geeksforgeeks.org/what-is-class-invariant/

        struct Point2D
        {
            Point2D() : Point2D{ 0, 0 } {}
            Point2D(int x, int y) : m_x{ x }, m_y{ y } {}

            int m_x{};
            int m_y{};
        };

        class Game
        {
        private:
            int     m_width;       // right bound 
            int     m_height;      // height bound 
            Point2D m_position;    // position of a figure on the game board

        public:
            Game(int width, int height, Point2D position)
                : m_width{}, m_height{}, m_position{ m_position }
            {
                // ensure that the object was constructed correctly 
                checkInvariant();
            }

            void moveTo(Point2D inc)
            {
                m_position.m_x += inc.m_x;
                m_position.m_y += inc.m_y;

                // ensure that the figure wasn't moved out of play bounds 
                checkInvariant();
            }

            // calling 'checkInvariant' is unnecessary because this is an accessor method 
            Point2D getLoc() const
            {
                return m_position;
            }

        private:
            void checkInvariant() const
            {
                assert(m_position.m_x >= 0 && m_position.m_x <= m_width);
                assert(m_position.m_y >= 0 && m_position.m_y <= m_height);
            }
        };

        static void guidelines_inheritance_invariants()
        {
            Game game{ 30, 20, Point2D{ 5, 5 } };

            // will throw assert error because the position is out of bounds
            game.moveTo(Point2D{ 20, 20 });

            // game is being spawned out of bounds 
            Game anotherGame{ 10, 10, Point2D{ 12, 8 } };
        }

        // =======================================================================
        // The new syntax "= default" in C++11

        class A
        {
        public:
            int m_x;
            A() {}
        };

        class B
        {
        public:
            int m_x;
            B() = default;
            B(int x) : m_x{ x } {}
        };

        static void guidelines_defaulted_constructor()
        {
            A a;
            B b;
        }

        // =======================================================================
        // Write Small, Focused Functions

        static bool isValidUsername(const std::string& username) {

            const auto MinLength{ 8 };
            const auto MaxLength{ 30 };

            const std::string ValidCharacters{
                "abcdefghijklmnopqrstuvwxyz0123456789_-."
            };

            if (username.length() < MinLength || username.length() > MaxLength) {
                return false;
            }

            for (char ch : username) {
                if (ValidCharacters.find(ch) == std::string::npos) {
                    return false;
                }
            }

            return true;
        }

        // =======================================================================
        // Use 'const' liberally

        class Rectangle
        {
        private:
            double m_width;
            double m_height;

        public:
            Rectangle(double width, double height)
                : m_width{ width }, m_height{ height }
            {
            }

            double area() const {
                return  m_width * m_height;
            }

            void scale(double factor) {
                m_width *= factor;
                m_height *= factor;
            }
        };

        static void printArea(const Rectangle& rect) {
            std::println("Area: {}", rect.area());
        }

        // =======================================================================
        // Prefer Exceptions over Error Codes

        static void error_handling_01() {

            try {
                std::ifstream file("data.txt");

                if (!file.is_open()) {
                    throw std::runtime_error("Could not open file");
                }

                // Process the file
            }
            catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            }
        }

        static void error_handling_02() {

            std::ifstream file("data.txt");

            if (!file.is_open()) {
                // Handle the error, maybe return an error code  
            }

            // Process the file
        }
    }

    // =======================================================================
    // Return Type of Methods

    namespace GuidelinesCoreCpp_MethodsReturnType_CopiedToCaller {

        class Person
        {
        private:
            std::string   m_name;
            size_t        m_age;

        public:
            Person() = default;
            Person(const std::string& name, size_t age)
                : m_name{ name }, m_age{ age }
            {}

            std::string getName() const { return m_name; }
            size_t getAge() const { return m_age; }
        };

        static void test_person() {
            Person jack{ "Jack", 50 };
            std::string name{ jack.getName() };
            std::println("Name: {}", name);
        }
    }

    namespace GuidelinesCoreCpp_MethodsReturnType_LifetimeByVoucher {

        class Person
        {
        private:
            std::string   m_name;
            size_t        m_age;

        public:
            Person() = default;
            Person(const std::string& name, size_t age)
                : m_name{ name }, m_age{ age }
            {}

            const std::string& getName() const { return m_name; }
            size_t getAge() const { return m_age; }
        };

        static void test_person() {
            Person jack{ "Jack", 50 };
            const std::string& name{ jack.getName() };
            std::println("Name: {}", name);
        }
    }

    // =======================================================================
    // Prefer Composition over Inheritance

    namespace GuidelinesCoreCpp_CompositionOverInheritance {

        class Vector3D{};

        class Transform {
            Vector3D m_position;
            Vector3D m_rotation;
            Vector3D m_scale;
        };

        class Character
        {
        public:
            // functions that might use *m_transform* if they need it

        private:
            Transform m_transform;
        };

        class Obstacle
        {
        public:
            // functions that might use *m_transform* if they need it

        private:
            Transform m_transform;
        };
    }

    // =======================================================================
    // Prevent Implicit Conversions

    namespace GuidelinesCoreCpp_PreventImplicitConversions {

        // demonstrating implicit conversion
        class Distance
        {
        private:
            int m_meters;

        public:
            /*explicit*/ Distance(int meters)             // put explicit into comment / remove comment
                : m_meters{ meters }
            {}

            void display() const {
                std::println("Distance: {}", m_meters);
            }
        };

        static void printDistance(const Distance& d) {
            d.display();
        }

        static void guidelines_implicit_conversion()
        {
            auto meters{ 10 };
            printDistance(meters); // implicit conversion: int ==> Distance
            // or
            // printDistance(static_cast<Distance>(meters));  
        }
    }

    // =======================================================================
    // Prevent Implicit Conversions

    namespace GuidelinesCoreCpp_Keyword_Auto {

        static void guidelines_keyword_auto_01()
        {
            std::map<int, std::string> aMap{ { 1, "Hello"  } };

            std::map<int, std::string>::iterator it{ aMap.begin() };

            // std::pair<int, std::string>& entry1{ *it };  // Why this line DOES NOT compile ???

            auto& entry2{ *it };
        }

        class Person
        {
        private:
            std::string   m_name;

        public:
            Person() = default;
            Person(const std::string& name) : m_name{ name } {}

            const std::string& getName() const { return m_name; }
        };

        static void guidelines_keyword_auto_02()
        {
            Person jack{ "Jack" };
            auto& name = jack.getName();
        }

        static void guidelines_keyword_auto()
        {
            guidelines_keyword_auto_01();
            guidelines_keyword_auto_02();
        }
    }
}

void guidelines_core_cpp()
{
    using namespace GuidelinesCoreCpp;

    // guidelines_inheritance_invariants();   // crashes intentionally
    //guidelines_defaulted_constructor();
    GuidelinesCoreCpp_PreventImplicitConversions::guidelines_implicit_conversion();
    GuidelinesCoreCpp_Keyword_Auto::guidelines_keyword_auto();
}

// ===========================================================================
// End-of-File
// ===========================================================================

static void test_03() {


}

