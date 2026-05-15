/*
 *  aes_unavailable.h
 *
 *  Copyright (C) 2024, 2025, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the AESUnavailable object which serves as a
 *      stub for when specific AES engines when they are not available.
 *      For example, if one builds the code with Intel Intrinsics disabled,
 *      then the AESIntel object will be an alias of this object.
 *
 *      This helps to simplify code to avoid having conditional compilation
 *      statements.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <span>
#include <cstdint>
#include <terra/crypto/cipher/aes.h>

namespace Terra::Crypto::Cipher::AES
{

class AESUnavailable : public AESEngine
{
    public:
        AESUnavailable() = default;
        AESUnavailable(const AESUnavailable &) = default;
        AESUnavailable(AESUnavailable &&)  = default;
        ~AESUnavailable() override = default;

        AESUnavailable &operator=(const AESUnavailable &) = default;
        AESUnavailable &operator=(AESUnavailable &&) = default;

        AESEngineType GetEngineType() const noexcept override
        {
            return AESEngineType::Unavailable;
        }

        void SetKey([[maybe_unused]] std::span<const std::uint8_t> key) override
        {
        }

        void ClearKeyState() override {}

        void Encrypt(
            [[maybe_unused]] std::span<const std::uint8_t, 16> plaintext,
            [[maybe_unused]] std::span<std::uint8_t, 16> ciphertext) noexcept
            override
        {
        }

        void Decrypt(
            [[maybe_unused]] std::span<const std::uint8_t, 16> ciphertext,
            [[maybe_unused]] std::span<std::uint8_t, 16> plaintext) noexcept
            override
        {
        }

        bool operator==([[maybe_unused]] const AESUnavailable &other) const
        {
            return true;
        }

        bool operator!=([[maybe_unused]] const AESUnavailable &other) const
        {
            return false;
        }
};

} // namespace Terra::Crypto::Cipher::AES
