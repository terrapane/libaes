/*
 *  cpu_check.cpp
 *
 *  Copyright (C) 2024, 2025, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This module declares a function that will verify that the Intel
 *      processor supports the AES-NI instructions.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

namespace Terra::Crypto::Cipher::AES
{

bool CPUSupportsAES_NI();

} // namespace Terra::Crypto::Cipher::AES
