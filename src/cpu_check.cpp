/*
 *  cpu_check.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This module defines a function that will verify that the Intel
 *      processor supports the AES-NI instructions.  When calling the cpuid()
 *      function with function_id 1, bit 25 of the ecx register will contain
 *      a 1 if the AES-NI instructions are supported.  Source:
 *      https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
 *
 *  Portability Issues:
 *      None.
 */

#include <cstdint>
#ifdef __linux__
#include <cpuid.h>
#endif
#ifdef _WIN32
#include <array>
#include <intrin.h>
#endif
#include "intel_intrinsics.h"

namespace Terra::Crypto::Cipher
{

#ifdef TERRA_USE_INTEL_AES_INTRINSICS

// Set the feature bit representing AES (25th bit) (0x0200'0000)
constexpr std::uint32_t Intel_AES_Bit = 0x0200'0000;

#ifdef _WIN32

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::array<int, 4> cpu_info{};
        __cpuid(cpu_info.data(), 0);
        if (cpu_info[0] < 1) return false;
    }

    std::array<int, 4> cpu_info{};
    __cpuid(cpu_info.data(), 1);
    return (cpu_info[2] & Intel_AES_Bit) != 0;
}

#else

#ifdef __linux__

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::uint32_t eax{}, ebx{}, ecx{}, edx{};
        __cpuid(0, eax, ebx, ecx, edx);
        if (eax < 1) return false;
    }

    std::uint32_t eax{}, ebx{}, ecx{}, edx{};
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & Intel_AES_Bit) != 0;
}

#else // __linux__

#define cpuid(function_id, eax, ebx, ecx, edx) \
    __asm__ __volatile__ ("cpuid": "=a" (eax), "=b" (ebx), "=c" (ecx), \
                                   "=d" (edx) : "a" (function_id));

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::uint32_t eax{}, ebx{}, ecx{}, edx{};
        cpuid(0, eax, ebx, ecx, edx);
        if (eax < 1) return false;
    }

    std::uint32_t eax{}, ebx{}, ecx{}, edx{};
    cpuid(1, eax, ebx, ecx, edx);
    return (ecx & Intel_AES_Bit) != 0;
}

#endif // __linux__

#endif // _WIN32

#else // TERRA_USE_INTEL_AES_INTRINSICS

bool CPUSupportsAES_NI()
{
    return false;
}

#endif // TERRA_USE_INTEL_AES_INTRINSICS

} // namespace Terra::Crypto::Cipher
