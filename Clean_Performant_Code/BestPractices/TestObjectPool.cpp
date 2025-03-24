// ===========================================================================
// TestObjectPool.cpp // Best Practices
// ===========================================================================

#include "ObjectPool.h"

#include <string>

class Person
{
private:
    std::string m_first;
    std::string m_last;
    size_t      m_age;

public:
    Person(std::string first, std::string last, size_t age) 
        : m_first{ first }, m_last{ last }, m_age{ age } 
    {}

    ~Person(){
        std::println("d'tor Person");
    }
};

void object_pool_best_practices_01()
{
    using PersonPool = ObjectPool<Person>;

    PersonPool pool{};

    {
        auto person { pool.acquireObject("Sepp", "Mueller", (size_t) 30)};
    }

    std::println("Done.");
}

void object_pool_best_practices()
{
    object_pool_best_practices_01();
}

// ===========================================================================
// End-of-File
// ===========================================================================
