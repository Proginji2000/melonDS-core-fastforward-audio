/*
    Copyright 2016-2025 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#ifndef ARCODEVALIDATOR_H
#define ARCODEVALIDATOR_H

#include <cstddef>
#include <vector>

#include "types.h"

namespace melonDS
{

enum class ARCodeValidationError
{
    None,
    Empty,
    OddWordCount,
    TruncatedEPayload,
};

struct ARCodeValidationResult
{
    ARCodeValidationError Error = ARCodeValidationError::None;
    std::size_t InstructionIndex = 0;
    u32 PayloadBytes = 0;
    std::size_t AvailablePayloadBytes = 0;

    [[nodiscard]] bool IsValid() const noexcept
    {
        return Error == ARCodeValidationError::None;
    }
};

[[nodiscard]] constexpr std::size_t ARCodePayloadWordCount(u32 payloadBytes) noexcept
{
    return static_cast<std::size_t>(((static_cast<u64>(payloadBytes) + 7) / 8) * 2);
}

[[nodiscard]] inline ARCodeValidationResult ValidateARCode(const std::vector<u32>& code) noexcept
{
    if (code.empty())
        return {ARCodeValidationError::Empty};
    if ((code.size() & 1) != 0)
        return {ARCodeValidationError::OddWordCount};

    std::size_t wordIndex = 0;
    std::size_t instructionIndex = 0;
    while (wordIndex < code.size())
    {
        const u8 opcode = code[wordIndex] >> 24;
        const u32 payloadBytes = code[wordIndex + 1];
        wordIndex += 2;
        instructionIndex++;

        if ((opcode & 0xF0) != 0xE0)
            continue;

        const std::size_t payloadWords = ARCodePayloadWordCount(payloadBytes);
        const std::size_t availableWords = code.size() - wordIndex;
        if (payloadWords > availableWords)
        {
            return {
                ARCodeValidationError::TruncatedEPayload,
                instructionIndex,
                payloadBytes,
                availableWords * sizeof(u32),
            };
        }
        wordIndex += payloadWords;
    }

    return {};
}

}

#endif // ARCODEVALIDATOR_H
