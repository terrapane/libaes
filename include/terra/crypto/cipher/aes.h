/*
 *  aes.h
 *
 *  Copyright (C) 2024, 2025, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the AES object that performs encryption and
 *      decryption as specified in FIPS 197 ("Advanced Encryption Standard").
 *      This object utilizes one of the underlying AES engines to perform
 *      the actual encryption.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <stdexcept>
#include <cstdint>
#include <cstddef>
#include <span>
#include <memory>

namespace Terra::Crypto::Cipher::AES
{

// Define an exception class for AES-related exceptions
class AESException : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

// Enum that defines the AES engine types
enum class AESEngineType : std::uint8_t
{
    Unavailable,
    Universal,
    Intel
};

// Define an interface class to facilitate a plurality of AES implementations
class AESEngine
{
    public:
        AESEngine() = default;
        AESEngine(const AESEngine &) = delete;
        AESEngine(AESEngine &&) = default;
        virtual ~AESEngine() = default;

        AESEngine &operator=(const AESEngine &) = delete;
        AESEngine &operator=(AESEngine &&) = default;

        virtual AESEngineType GetEngineType() const noexcept = 0;

        virtual void SetKey(std::span<const std::uint8_t> key) = 0;

        virtual void ClearKeyState() = 0;

        virtual void Encrypt(
            std::span<const std::uint8_t, 16> plaintext,
            std::span<std::uint8_t, 16> ciphertext) noexcept = 0;

        virtual void Decrypt(
            std::span<const std::uint8_t, 16> ciphertext,
            std::span<std::uint8_t, 16> plaintext) noexcept = 0;
};

// Define the AES class
class AES
{
    public:
        AES();
        explicit AES(std::span<const std::uint8_t> key);
        AES(const AES &other);
        AES(AES &&other) noexcept;
        ~AES() = default;

        AES &operator=(const AES &other);
        AES &operator=(AES &&other) noexcept;

        void SetKey(std::span<const std::uint8_t> key);

        void Encrypt(std::span<const std::uint8_t, 16> plaintext,
                     std::span<std::uint8_t, 16> ciphertext) noexcept;

        void Decrypt(std::span<const std::uint8_t, 16> ciphertext,
                     std::span<std::uint8_t, 16> plaintext) noexcept;

        bool operator==(const AES &other) const;
        bool operator!=(const AES &other) const;

    protected:
        void CreateEngine();

        std::unique_ptr<AESEngine> aes_engine;  // AES engine
};

} // namespace Terra::Crypto::Cipher::AES
