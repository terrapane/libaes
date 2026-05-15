/*
 *  aes_utilities.h
 *
 *  Copyright (C) 2024, 2025, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This header file defines some constexpr functions that are defined
 *      in the AES specification or facilitate AES-related operations.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <terra/bitutil/bit_rotation.h>
#include "aes_tables.h"
#include "aes_definitions.h"

namespace Terra::Crypto::Cipher::AES
{

/*
 *  GetWordFromBuffer
 *
 *  Description:
 *      This function will read a 32-bit word from the given buffer at the
 *      specified offset.  It is used in several places in AES, including
 *      the  key expansion logic and filling a column in the state
 *      array as shown in Figure 3 of FIPS 197.
 *
 *  Parameters:
 *      buffer [in]
 *          A pointer to the buffer from which octets will be read to form a
 *          32-bit value.
 *
 *      offset [in]
 *          The offset from which to read from the buffer.
 *
 *  Returns:
 *      A 32-bit word extract from the given buffer at the specified offset.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 GetWordFromBuffer(std::span<const std::uint8_t> buffer,
                                     const std::size_t offset)
{
    return static_cast<AESInt32>(buffer[(offset << 2U)    ]) << 24U |
           static_cast<AESInt32>(buffer[(offset << 2U) + 1]) << 16U |
           static_cast<AESInt32>(buffer[(offset << 2U) + 2]) <<  8U |
           static_cast<AESInt32>(buffer[(offset << 2U) + 3]);
}

/*
 *  PutStateColumn
 *
 *  Description:
 *      This function takes the given value from the state array as input
 *      and puts that column into the given buffer linearly.  This is the
 *      output transformation shown in Figure 3 of FIP 197.
 *
 *  Parameters:
 *      value [in]
 *          The state array value for specified column.
 *
 *      column [in]
 *          The column in the state array from which values are to be extracted.
 *          This must be constrained to values between 0 and 3, but no error
 *          checking is performed here for performance reasons.
 *
 *      ciphertext [out]
 *          A pointer into the ciphertext output buffer to write the 32-bit
 *          word extract from the state array.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void PutStateColumn(const AESInt32 value,
                              const std::size_t column,
                              std::span<std::uint8_t, 16> ciphertext)
{
    ciphertext[(column << 2U)    ] = (value >> 24U) & 0xffU;
    ciphertext[(column << 2U) + 1] = (value >> 16U) & 0xffU;
    ciphertext[(column << 2U) + 2] = (value >>  8U) & 0xffU;
    ciphertext[(column << 2U) + 3] = (value       ) & 0xffU;
}

/*
 *  RotWord
 *
 *  Description:
 *      This function will left rotate a 32-bit word by 8 bits.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word to be rotated left by 8 bits.
 *
 *  Returns:
 *      The 32-bit word after the bits are rotated left.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 RotWord(const AESInt32 word)
{
    return Terra::BitUtil::RotateLeft(word,
                                      8,
                                      32,
                                      static_cast<AESInt32>(0xffff'ffff));
}

/*
 *  SubBytes
 *
 *  Description:
 *      This function will perform byte substitution using the S-box table.
 *
 *  Parameters:
 *      value [in]
 *          The value to be substituted using the S-box table.
 *
 *  Returns:
 *      The substituted octet.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 SubBytes(const AESInt32 value)
{
    return static_cast<AESInt32>(
        static_cast<AESInt32>(std::span(Sbox)[(value >> 24U) & 0xffU]) << 24U |
        static_cast<AESInt32>(std::span(Sbox)[(value >> 16U) & 0xffU]) << 16U |
        static_cast<AESInt32>(std::span(Sbox)[(value >>  8U) & 0xffU]) <<  8U |
        static_cast<AESInt32>(std::span(Sbox)[(value       ) & 0xffU]));
}

/*
 *  SubBytesShiftRows
 *
 *  Description:
 *      This function perform byte substitution while also shifting rows.
 *      This is part of the final encryption round.
 *
 *  Parameters:
 *      column
 *          The column shift value.
 *
 *      state [in]
 *          The state table from which to extract values while doing byte
 *          substitution using the S-box table.
 *
 *  Returns:
 *      The 32-bit value resulting from the byte substitution following the
 *      column mixing scheme.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 SubBytesShiftRows(std::size_t column,
                                     std::span<const AESInt32, 4> state)
{
    const AESInt32 octet1 =
            std::span(Sbox)[(state[(0 + column) % 4] >> 24U) & 0xffU] << 24U;
    const AESInt32 octet2 =
            std::span(Sbox)[(state[(1 + column) % 4] >> 16U) & 0xffU] << 16U;
    const AESInt32 octet3 =
            std::span(Sbox)[(state[(2 + column) % 4] >>  8U) & 0xffU] <<  8U;
    const AESInt32 octet4 =
            std::span(Sbox)[(state[(3 + column) % 4]      ) & 0xffU];

    return octet1 | octet2 | octet3 | octet4;
}

/*
 *  InvSubBytesShiftRows
 *
 *  Description:
 *      This function perform byte inverse substitution while also shifting
 *      rows.  This is part of the final decryption round.
 *
 *  Parameters:
 *      column
 *          The column shift value.
 *
 *      state [in]
 *          The state table from which to extract values while doing byte
 *          substitution using the S-box table.
 *
 *  Returns:
 *      The 32-bit value resulting from the byte substitution following the
 *      column mixing scheme.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 InvSubBytesShiftRows(std::size_t column,
                                        std::span<const AESInt32, 4> state)
{
    const AESInt32 octet1 =
        std::span(InverseSbox)[(state[(0 + column) % 4] >> 24U) & 0xffU] << 24U;
    const AESInt32 octet2 =
        std::span(InverseSbox)[(state[(3 + column) % 4] >> 16U) & 0xffU] << 16U;
    const AESInt32 octet3 =
        std::span(InverseSbox)[(state[(2 + column) % 4] >>  8U) & 0xffU] <<  8U;
    const AESInt32 octet4 =
        std::span(InverseSbox)[(state[(1 + column) % 4]) & 0xffU];

    return octet1 | octet2 | octet3 | octet4;
}

/*
 *  AddRoundKey
 *
 *  Description:
 *      The AddRoundKey function merely XORs two values.  It is defined
 *      as a constexpr function just to make it easier to understand the
 *      code as it compares to the AES specification.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr AESInt32 AddRoundKey(const AESInt32 x, const AESInt32 y)
{
    return x ^ y;
}

/*
 *  MixColShiftRow
 *
 *  Description:
 *      This function, by using the encrypting constants tables Enc0..Enc3,
 *      is able to perform SubBytes(), ShiftRows(), and MixColumns() for a
 *      column in the state array efficiently.
 *
 *  Parameters:
 *      column [in]
 *          The column number in the state array to operate upon.
 *
 *      state [in]
 *          The state array on which to operate.
 *
 *  Returns:
 *      The resulting output of the combined SubBytes(), ShiftRows(), and
 *      MixColumns() operations.
 *
 *  Comments:
 *      The constants added to column performs the row shifts.
 */
constexpr AESInt32 MixColShiftRow(const std::size_t column,
                                  std::span<const AESInt32, 4> state)
{
    return static_cast<AESInt32>(
        std::span(Enc0)[(state[(0 + column) % 4] >> 24U) & 0xffU] ^
        std::span(Enc1)[(state[(1 + column) % 4] >> 16U) & 0xffU] ^
        std::span(Enc2)[(state[(2 + column) % 4] >>  8U) & 0xffU] ^
        std::span(Enc3)[(state[(3 + column) % 4]       ) & 0xffU]);
}

/*
 *  FastInvMixColumn
 *
 *  Description:
 *      This function will perform the InverseMixColumns operation for
 *      the given 32-bit word.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word value on which to operate.
 *
 *  Returns:
 *      The resulting value for InvMixColumns() given the 32-bit input value.
 *
 *  Comments:
 *      Throughout most of the decryption process the decrypting constants
 *      tables (Dec0..Dec3) are used as-is, since they contain the result of
 *      the InverseMixColumns(InvSubBytes()).  As a part of the process to
 *      expand the decryption key, however, it is necessary to perform this
 *      step without byte substitution.  (Refer to the bottom of Figure 15
 *      of FIP 197 for the algorithm.)
 *
 *      This function exists to "reverse" the byte substitution already
 *      existing in the decrypting constants table before indexing into those
 *      tables.  This requires an additional lookup to get the proper entry
 *      in the table, but it is still fast and avoids the need to maintain
 *      additional tables.
 *
 *      This is used by the decryption round key generation as explained in
 *      section 5.3.5 of FIPS 197.  Refer to the README.md for more detail.
 */
constexpr AESInt32 FastInvMixColumn(const AESInt32 value)
{
    return static_cast<AESInt32>(
        std::span(Dec0)[std::span(Sbox)[(value >> 24U) & 0xffU]] ^
        std::span(Dec1)[std::span(Sbox)[(value >> 16U) & 0xffU]] ^
        std::span(Dec2)[std::span(Sbox)[(value >>  8U) & 0xffU]] ^
        std::span(Dec3)[std::span(Sbox)[(value       ) & 0xffU]]);
}

/*
 *  InvMixColShiftRow
 *
 *  Description:
 *      This function, by using the decrypting constants tables Dec0..Dec3,
 *      is able to perform InvSubBytes(), InvShiftRows(), and InvMixColumns()
 *      for a column in the state array efficiently.
 *
 *  Parameters:
 *      column [in]
 *          The column number in the state array to operate upon.
 *
 *      state [in]
 *          The state array on which to operate.
 *
 *  Returns:
 *      The resulting output of the combined InvSubBytes(), InvShiftRows(), and
 *      InvMixColumns() operations.
 *
 *  Comments:
 *      The constants added to column performs the row shifts.
 */
constexpr AESInt32 InvMixColShiftRow(const std::size_t column,
                                     std::span<const AESInt32, 4> state)
{
    return static_cast<AESInt32>(
        std::span(Dec0)[(state[(0 + column) % 4] >> 24U) & 0xffU] ^
        std::span(Dec1)[(state[(3 + column) % 4] >> 16U) & 0xffU] ^
        std::span(Dec2)[(state[(2 + column) % 4] >>  8U) & 0xffU] ^
        std::span(Dec3)[(state[(1 + column) % 4]       ) & 0xffU]);
}

} // namespace Terra::Crypto::Cipher::AES
