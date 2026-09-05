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

#ifndef POKEMONWHITEAUDIO_H
#define POKEMONWHITEAUDIO_H

#include <array>
#include <atomic>
#include <vector>

#include "types.h"

namespace melonDS
{
class NDS;
class ARM;

namespace NDSCart
{
class CartCommon;
}

enum class PokemonWhiteAudioClass : u8
{
    Unknown,
    BGM,
    ME,
    SFX,
};

struct RuntimeSeqClassification
{
    bool Active = false;
    u16 SeqId = 0xFFFF;
    u8 PlayerInfo = 0xFF;
    PokemonWhiteAudioClass Class = PokemonWhiteAudioClass::Unknown;
};

class PokemonWhiteAudioClassifier
{
public:
    explicit PokemonWhiteAudioClassifier(NDS& nds) noexcept;

    void Initialize(const NDSCart::CartCommon* cart);
    void ResetRuntime() noexcept;
    void RebuildRuntime();
    void SetBgmGateDivisor(u32 requested) noexcept;

    [[nodiscard]] static constexpr bool IsGateHookAddress(u32 address) noexcept
    {
        return address == SeqPlayerGateAddress;
    }
    [[nodiscard]] bool IsHookAddress(u32 address) const noexcept
    {
        return Enabled && (address == StartFunctionAddress
            || address == StartHookAddress
            || address == StopHookAddress
            || IsGateHookAddress(address)
            || address == ExChannelMainAddress
            || address == ExChannelLoopAddress);
    }
    [[nodiscard]] bool HandleARM7Hook(u32 address);

private:
    struct SSEQEntry
    {
        const u8* File = nullptr;
        u32 FileSize = 0;
        u32 DataOffset = 0;
        u16 SeqId = 0xFFFF;
        u8 PlayerInfo = 0xFF;
        PokemonWhiteAudioClass Class = PokemonWhiteAudioClass::Unknown;
    };

    struct PendingStart
    {
        bool Valid = false;
        u32 Pointer = 0;
        u32 Offset = 0;
        const SSEQEntry* Entry = nullptr;
    };

    struct GatePhaseState
    {
        u32 ObservedEpoch = 0;
        u8 Phase = 0;
    };

    static constexpr u32 StartFunctionAddress = 0x0380171C;
    static constexpr u32 StartHookAddress = 0x038018C8;
    static constexpr u32 StopHookAddress = 0x03802114;
    static constexpr u32 SeqPlayerGateAddress = 0x03801608;
    static constexpr u32 ExChannelMainAddress = 0x03800A5C;
    static constexpr u32 ExChannelLoopAddress = 0x03800A7C;
    static constexpr u32 ExChannelReleaseAddress = 0x0380214C;

    bool BuildCache(const u8* sdat, u32 size);
    void ClassifyPlayer(u32 player, bool usePending = false);
    void ReceiveStart(u32 player, u32 pointer, u32 offset);
    const SSEQEntry* Resolve(u32 pointer, u32& matches) const;
    const u8* GetGuestRange(u32 address, u32 size) const;
    void ClearPlayer(u32 player);
    [[nodiscard]] u32 AdvanceGateEpoch() noexcept;
    [[nodiscard]] u32 PublishGateDivisor(u32 divisor) noexcept;
    static void SynchronizeGatePhase(GatePhaseState& phase, u32 gateState) noexcept;
    void ResetGatePhases(u32 gateState) noexcept;
    [[nodiscard]] bool HandleSeqPlayerGate();
    void HandleExChannelMain() noexcept;
    void HandleExChannelLoop();
    [[nodiscard]] bool ResolveExChannelOwner(u32 channel, u32& ownerPlayer) const;

    NDS& NDS;
    bool Enabled = false;
    std::vector<SSEQEntry> Cache;
    std::array<RuntimeSeqClassification, 16> Runtime {};
    std::array<PendingStart, 16> Pending {};
    std::array<GatePhaseState, 16> GatePhases {};
    u32 ExChannelMainUpdate = 0;
    std::atomic<u32> GateState {0};
};

bool PokemonWhiteAudioJITHook(ARM* cpu, u32 address);

} // namespace melonDS

#endif // POKEMONWHITEAUDIO_H
