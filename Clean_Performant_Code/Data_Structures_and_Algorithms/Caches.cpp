// ===========================================================================
// Caches.cpp
// ===========================================================================

#include "../LoggerUtility/ScopedTimer.h"

#include <array>
#include <print>
#include <cstdlib>

#define WIN32_LEAN_AND_MEAN 
#include <windows.h>
#include <processthreadsapi.h>

namespace DataStructuresAndAlgorithms {

    namespace CacheLinesAndCacheSizes {

        static void test_examine_cache_line_size() {

            constexpr auto cachelineSize = std::hardware_destructive_interference_size;

            std::println("Cache Line Size: {}", cachelineSize);
        }

        static void test_examine_l1_cache_size() {

            // https://gist.github.com/kimwalisch/16c34ae16447b245464a

            typedef BOOL(WINAPI* LPFN_GLPI)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);

            auto handle = GetModuleHandle(L"kernel32");

            auto glpi = (LPFN_GLPI)GetProcAddress(handle, "GetLogicalProcessorInformation");
            if (glpi == NULL)
                return;

            DWORD bufferBytes = 0;
            int cacheSize = 0;

            // calculate buffer length
            BOOL ret = glpi(0, &bufferBytes);

            std::size_t size = bufferBytes / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);

            SYSTEM_LOGICAL_PROCESSOR_INFORMATION* buffer = new SYSTEM_LOGICAL_PROCESSOR_INFORMATION[size];

            // retrieve array of SYSTEM_LOGICAL_PROCESSOR_INFORMATION structures
            ret = glpi(buffer, &bufferBytes);

            for (std::size_t i = 0; i < size; i++)
            {
                if (buffer[i].Relationship == RelationCache && buffer[i].Cache.Level == 1)
                {
                    cacheSize = (int)buffer[i].Cache.Size;
                    break;
                }
            }

            delete[] buffer;

            auto cacheSizeKB = cacheSize / 1024;
            std::println("L1 Cache Size: {} kB", cacheSizeKB);
        }
    }

    namespace CacheMisses {

        constexpr auto capacityL1CacheSize = 32768; // L1 Data Cache Size

        constexpr auto Size = capacityL1CacheSize / sizeof(int);

        using MatrixType = std::array<std::array<size_t, Size>, Size>;

        static MatrixType matrix;

        static auto initMatrix(MatrixType& matrix) {

            ScopedTimer watch{};

            size_t value{};

            for (size_t i{}; i != Size; ++i) {
                for (size_t j{}; j != Size; ++j) {
                    matrix[i][j] = value++;      // no "cache thrashing"
                    //matrix[j][i] = value++;    // remove comment: demonstrates "cache thrashing"
                }
            }
        }

        static void test_cache_thrashing() {
            initMatrix(matrix);
        }
    }
}

// =================================================================

void test_caches()
{
    using namespace DataStructuresAndAlgorithms::CacheLinesAndCacheSizes;
    test_examine_cache_line_size();
    test_examine_l1_cache_size();

    using namespace DataStructuresAndAlgorithms::CacheMisses;
    test_cache_thrashing();
}

// ===========================================================================
// End-of-File
// ===========================================================================
