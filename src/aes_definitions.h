/*
 *  aes_definitions.h
 *
 *  Copyright (C) 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines types and constants used by the AES universal cipher.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <climits>
#include <cstdint>

namespace Terra::Crypto::Cipher::AES
{

// Define the 32-bit (or larger) integer type used by the AESUniversal cipher
using AESInt32 = std::uint_fast32_t;
static_assert(sizeof(AESInt32) * CHAR_BIT >= 32);

} // namespace Terra::Crypto::Cipher::AES
