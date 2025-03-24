// ===========================================================================
// Guidelines_Inheritance.cpp
// ===========================================================================

#include <cassert>
#include <print>

namespace GuidelinesInheritance {

    // =======================================================================
    // Class Hierarchy

    class DrawableUIElement {
    public:
        virtual void render() const = 0;
        // ...
    };

    class AbstractButton : public DrawableUIElement {
    public:
        virtual void onClick() = 0;
        // ...
    };

    class PushButton : public AbstractButton {
        virtual void render() const override {};
        virtual void onClick() override {};
        // ...
    };

    class Checkbox : public AbstractButton {
        // ...
    };

    // =======================================================================
    // Comparison virtual / non virtual methods

    namespace GuidelinesInheritance_Comparison 
    {
        class A
        {
        public:
            void func() {};
        };

        class Base
        {
        public:
            virtual void func() {};
        };

        class Derived : public Base
        {
        public:
            virtual void func() override {};
        };

        class X
        {
        private:
            double m_value{};

        public:
            void func() {};
        };

        class Y
        {
        private:
            double m_value{};

        public:
            virtual void func() {};
        };

        static void guidelines_inheritance_virtual()
        {
            // comparison virtual / non-virtual method invocation
            A a;
            a.func();

            Base* bp;
            bp = new Derived();
            bp->func();

            // comparison object sizes of classes with / without virtual methods
            X x;
            Y y;

            std::println("Sizeof x: {}", sizeof(x));
            std::println("Sizeof y: {}", sizeof(y));
        }
    }

    // =======================================================================
    // Keyword 'override'

    namespace GuidelinesInheritance_Keyword_Override
    {
        class Base
        {
        public:
            // user wants to override this method in the derived class
            virtual void func() { std::println("In base class"); }
        };

        class Derived : public Base
        {
        public:
            // did a silly mistake by putting an argument "int a"
            void func(int a) /*override*/   // <=== remove comment
            {
                std::println("In derived class");
            }
        };

        static void guidelines_inheritance_keyword_override()
        {
            Base base;
            Derived derived;
            std::println("Compiles successfully");

            Base* bp;
            bp = &derived;
            bp->func();
        }
    }

    // =======================================================================
    // Keyword 'final'

    namespace GuidelinesInheritance_Keyword_Final_01
    {
        struct Base {
            virtual void func() {};
        };

        struct Derived : public Base {
            void func() final {};                   // virtual as it overrides base::f
        };

        struct MostDerived : public Derived {
            // void func() {};                      // error: cannot override!
        };
    }

    namespace GuidelinesInheritance_Keyword_Final_02
    {
        struct Base /*final*/ {                     // <=== remove comment
            virtual void func() {};
        };

        struct Derived : public Base {
        };
    }

    namespace GuidelinesInheritance_Keyword_Final_03
    {
        class IAbstract
        {
        public:
            virtual void doSomething() = 0;
        };

        class CDerived : public IAbstract
        {
        private:
            int m_x{};

        public:
            void doSomething() final { m_x = 1; }

            void anotherMethod (void) { doSomething(); }
        };
    }

    // =======================================================================
// Keyword 'final'

    namespace GuidelinesInheritance_Virtual_BaseClassDestructor
    {
        class Base
        {
        public:
            /*virtual*/ ~Base() {
                std::println("d'tor Base");
            }

            virtual void doSomething() {}
        };

        class Derived : public Base
        {
        public:
            ~Derived() {
                std::println("d'tor Derived");
            }
        };

        static void test_base_class_destructor() {
            Base* bp = new Derived();
            delete bp;
        }
    }
}

void guidelines_inheritance()
{
    using namespace GuidelinesInheritance;

    GuidelinesInheritance_Comparison::guidelines_inheritance_virtual();
    GuidelinesInheritance_Keyword_Override::guidelines_inheritance_keyword_override();
    GuidelinesInheritance_Virtual_BaseClassDestructor::test_base_class_destructor();
}

// ===========================================================================
// End-of-File
// ===========================================================================
