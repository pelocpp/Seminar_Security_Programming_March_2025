// ===========================================================================
// CompileTimeHashStrings.cpp
// ===========================================================================

#include <iostream>
#include <print>
#include <unordered_map>

namespace MetaprogrammingHashExample {

    // =======================================================================
    // Metaprogramming: Hash Strings at Compile Time

    static constexpr auto hashFunction(const char* str) -> size_t {
        auto sum{ size_t{ 0 } };
        for (auto ptr{ str }; *ptr != '\0'; ++ptr)
            sum += *ptr;
        return sum;
    }

    static void metaprogramming_01()
    {
        constexpr auto hash = hashFunction("abc");
    }
}

namespace MetaprogrammingHashExample {

    // https://stackoverflow.com/questions/43435279/what-does-const-charan-mean
    // HIER SEHR GUT BESCHRIEBEN !!!!!!!!!!!!!!:
    // https://stackoverflow.com/questions/30981499/meaning-of-the-syntax-const-char-x
    // Arrays of unknown bound
    // https://en.cppreference.com/w/cpp/language/array 

    // =======================================================================
    // Metaprogramming: Example PrehashedString

    // Excursus: Passing an array to a function without decay
    // (without loss of the length of the array):
    // Syntax: const char (&x)[]
    // use a reference to an array of const char.
    // 
    // The main use of reference to an array is in a template
    // where the number of elements is than deduced

    template <typename T, size_t N>
    void useArray(const T(&a)[N])
    {
        size_t length{ N };
        std::println("Array Length: {} / First Element: {}", length, a[0]);
    }

    static void metaprogramming_02()
    {
        int array[] { 1, 2, 3, 4, 5};
        useArray(array);

        char chars[]{ "ABC"};
        useArray(chars);
    }
}

namespace MetaprogrammingHashExample {

    class PrehashedString
    {
    private:
        size_t      m_hash{};
        size_t      m_size{};
        const char* m_strptr{ nullptr };

    public:
        template <size_t N>
        constexpr PrehashedString(const char(&str)[N]) :
            m_hash{ hashFunction(&str[0]) },
            m_size{ N - 1 }, 
            m_strptr{ &str[0] }
        {}

        constexpr auto size() const { return m_size; }
        constexpr auto get_hash() const { return m_hash; }
        constexpr auto c_str() const -> const char* { return m_strptr; }

        auto operator== (const PrehashedString& other) const {
            return m_size == other.m_size &&
                std::equal(c_str(), c_str() + m_size, other.c_str());
        }

        auto operator!= (const PrehashedString& other) const {
            return !(*this == other);
        }
    };

    static void metaprogramming_03()
    {
        constexpr auto prehashed_string = PrehashedString{ 
            "this should be a long string" 
        };
        
        constexpr auto size{ prehashed_string.size() };
        constexpr auto hash{ prehashed_string.get_hash() };
        constexpr auto c_str{ prehashed_string.c_str() };
    }

    static void metaprogramming_04()
    {
        constexpr auto prehashed_string{ 
            PrehashedString{ "this should be a long string"  } 
        };
        
        constexpr auto size{ prehashed_string.size() };
        constexpr auto hash{ prehashed_string.get_hash() };
        constexpr auto c_str{ prehashed_string.c_str() };
    }
}

namespace std
{
    // =======================================================================
    // Metaprogramming: Example PrehashedString
    // std::hash

    // An overload of struct std::hash(), which simply returns the hash value.
    // This overload is used by std::unordered_map, std::unordered_set, or any
    // other class from the standard library that uses hash values.

    using namespace MetaprogrammingHashExample;

    template<>
    struct hash<PrehashedString> {
        constexpr auto operator() (const PrehashedString& s) const {
            return s.get_hash();
        }
    };
}

namespace MetaprogrammingHashExample {

    static constexpr auto test_prehashed_string() {

        const auto& hash_fn{ std::hash<PrehashedString>{} };
        const auto& str{ PrehashedString("abc") };
        return hash_fn(str);
    }

    static void metaprogramming_05()
    {
        constexpr auto hash{ test_prehashed_string() };
    }

    // dummy class Bitmap
    class Bitmap{};

    // external function which loads a bitmap from the filesystem
    static auto load_bitmap_from_filesystem(const char* path) -> Bitmap { return {}; }

    static auto get_bitmap_resource(const PrehashedString& path) -> const Bitmap&
    {
        // static storage of all loaded bitmaps
        static auto loaded_bitmaps = std::unordered_map<PrehashedString, Bitmap>{};

        // ff the bitmap is already in loaded_bitmaps, return it
        if (loaded_bitmaps.count(path) > 0) {
            return loaded_bitmaps.at(path);
        }
        
        // bitmap isn't already loaded, load and return it
        auto bitmap = load_bitmap_from_filesystem(path.c_str());

        loaded_bitmaps.emplace(path, std::move(bitmap));

        return loaded_bitmaps.at(path);
    }

    static auto draw_bitmap(const Bitmap& bm) {}

    static auto draw_bitmap() {
        const auto& bm = get_bitmap_resource("my_bitmap.png");
        draw_bitmap(bm);
    }

    static auto draw_bitmap_again() {
        const auto& bm = get_bitmap_resource("my_bitmap.png");
        draw_bitmap(bm);
    }

    static auto test_compile_time_hash_strings()
    {
        draw_bitmap();
        draw_bitmap_again();
    }
}

// =================================================================

void compile_time_hash_strings()
{
    using namespace MetaprogrammingHashExample;

    test_compile_time_hash_strings();
}

// ===========================================================================
// End-of-File
// ===========================================================================
