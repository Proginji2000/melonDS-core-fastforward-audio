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

#include "PokemonWhiteAudio.h"

#include <algorithm>
#include <cstring>

#include "ARM.h"
#include "MemRegion.h"
#include "NDS.h"
#include "NDSCart.h"
#include "sha1/sha1.hpp"
#define BYTE TEAKRA_SHA256_BYTE
#define WORD TEAKRA_SHA256_WORD
#include "teakra/src/makedsp1/sha256.h"
#undef WORD
#undef BYTE

namespace melonDS
{
namespace
{
constexpr u32 ROMSize = 0x10000000;
constexpr u32 SDATOffset = 0x0033E800;
constexpr u32 SDATSize = 0x03125600;

constexpr u32 PlayerBase = 0x0380A4FC;
constexpr u32 PlayerStride = 0x24;
constexpr u32 TrackBase = 0x0380A73C;
constexpr u32 TrackStride = 0x40;
constexpr u32 TrackCount = 32;
constexpr u32 ExChannelBase = 0x03809FBC;
constexpr u32 ExChannelStride = 0x54;
constexpr u32 ExChannelCount = 16;

constexpr u32 GateDivisorBits = 3;
constexpr u32 GateDivisorMask = 0x7;
constexpr u32 GateEpochMask = 0x1FFFFFFF;

constexpr u32 SanitizeGateDivisor(u32 divisor) noexcept
{
    return divisor >= 2 && divisor <= 4 ? divisor : 0;
}

constexpr u32 PackGateState(u32 epoch, u32 divisor) noexcept
{
    return ((epoch & GateEpochMask) << GateDivisorBits)
        | SanitizeGateDivisor(divisor);
}

constexpr u32 GateStateDivisor(u32 state) noexcept
{
    return state & GateDivisorMask;
}

constexpr u32 GateStateEpoch(u32 state) noexcept
{
    return state >> GateDivisorBits;
}

constexpr u32 NextGateState(u32 state, u32 divisor) noexcept
{
    return PackGateState(GateStateEpoch(state) + 1, divisor);
}

constexpr bool GateEpochChanged(u32 observedEpoch, u32 state) noexcept
{
    return observedEpoch != GateStateEpoch(state);
}

constexpr u8 GatePhaseAfterObservation(u32 observedEpoch, u8 phase, u32 state) noexcept
{
    return GateEpochChanged(observedEpoch, state) ? 0 : phase;
}

constexpr u32 GateTestOffN = PackGateState(7, 0);
constexpr u32 GateTestX2N1 = NextGateState(GateTestOffN, 2);
constexpr u32 GateTestX2ResetN2 = NextGateState(
    GateTestX2N1, GateStateDivisor(GateTestX2N1));
constexpr u32 GateTestX3N3 = NextGateState(GateTestX2ResetN2, 3);
constexpr u32 GateTestX4N4 = NextGateState(GateTestX3N3, 4);
constexpr u32 GateTestOffN5 = NextGateState(GateTestX4N4, 0);
static_assert(SanitizeGateDivisor(0) == 0);
static_assert(SanitizeGateDivisor(1) == 0);
static_assert(SanitizeGateDivisor(2) == 2);
static_assert(SanitizeGateDivisor(3) == 3);
static_assert(SanitizeGateDivisor(4) == 4);
static_assert(SanitizeGateDivisor(5) == 0);
static_assert(GateStateDivisor(GateTestOffN) == 0);
static_assert(GateStateDivisor(GateTestX2N1) == 2);
static_assert(GateStateDivisor(GateTestX2ResetN2) == 2);
static_assert(GateStateDivisor(GateTestX3N3) == 3);
static_assert(GateStateDivisor(GateTestX4N4) == 4);
static_assert(GateStateDivisor(GateTestOffN5) == 0);
static_assert(GateStateEpoch(GateTestX2N1) == 8);
static_assert(GateStateEpoch(GateTestX2ResetN2) == 9);
static_assert(GateStateEpoch(GateTestX3N3) == 10);
static_assert(GateStateEpoch(GateTestX4N4) == 11);
static_assert(GateStateEpoch(GateTestOffN5) == 12);
static_assert(PackGateState(7, 0) != PackGateState(7, 2));
static_assert(PackGateState(7, 2) != PackGateState(7, 3));
static_assert(PackGateState(7, 3) != PackGateState(7, 4));
static_assert(GateEpochChanged(GateStateEpoch(GateTestOffN), GateTestX2N1));
static_assert(GatePhaseAfterObservation(8, 1, GateTestX2ResetN2) == 0);
static_assert(GatePhaseAfterObservation(9, 1, GateTestX3N3) == 0);
static_assert(GatePhaseAfterObservation(10, 1, GateTestX4N4) == 0);
static_assert(GatePhaseAfterObservation(11, 1, GateTestOffN5) == 0);
static_assert(GatePhaseAfterObservation(12, 1, GateTestOffN5) == 1);

constexpr std::array<u8, 32> ExpectedROMSHA256 {
    0x0A, 0x7D, 0x6E, 0x87, 0xD9, 0x87, 0x8C, 0x2F,
    0xB9, 0x03, 0xBC, 0xCA, 0x01, 0xEC, 0xC8, 0xF9,
    0xA1, 0x86, 0xD0, 0xEE, 0xD1, 0x4D, 0xDB, 0xC8,
    0x79, 0x12, 0xAE, 0x12, 0x6F, 0xAA, 0x0B, 0xDB,
};

constexpr std::array<u8, 32> ExpectedSDATSHA256 {
    0x06, 0x20, 0x73, 0xD5, 0xE2, 0x9B, 0xC9, 0x53,
    0x97, 0x9D, 0x75, 0xF1, 0xBA, 0x4F, 0x5F, 0x26,
    0xD5, 0x3C, 0xB3, 0xFD, 0x41, 0x13, 0x06, 0x60,
    0xFE, 0x1B, 0xCA, 0x60, 0x41, 0x18, 0x9E, 0x13,
};

constexpr std::array<u8, 20> ExpectedARM7SHA1 {
    0x36, 0x42, 0x59, 0x35, 0x2F, 0xFF, 0xDC, 0xD1,
    0x5B, 0x75, 0xC2, 0xD9, 0xE9, 0x97, 0xD2, 0xED,
    0x0D, 0x87, 0x71, 0x90,
};

constexpr std::array<char, 12> ExpectedTitle {
    'P', 'O', 'K', 'E', 'M', 'O', 'N', ' ', 'W', 0, 0, 0,
};
constexpr std::array<char, 4> ExpectedGameCode {'I', 'R', 'A', 'F'};

u16 ReadLE16(const u8* data) noexcept
{
    return static_cast<u16>(data[0] | (data[1] << 8));
}

u32 ReadLE32(const u8* data) noexcept
{
    return static_cast<u32>(data[0])
        | (static_cast<u32>(data[1]) << 8)
        | (static_cast<u32>(data[2]) << 16)
        | (static_cast<u32>(data[3]) << 24);
}

bool IsRangeValid(u32 offset, u32 length, u32 total) noexcept
{
    return offset <= total && length <= total - offset;
}

bool SHA256Matches(const u8* data, u32 size, const std::array<u8, 32>& expected) noexcept
{
    SHA256_CTX context;
    std::array<u8, 32> digest;
    sha256_init(&context);
    sha256_update(&context, data, size);
    sha256_final(&context, digest.data());
    return digest == expected;
}

bool SHA1Matches(const u8* data, u32 size, const std::array<u8, 20>& expected) noexcept
{
    SHA1_CTX context;
    std::array<u8, 20> digest;
    SHA1Init(&context);
    SHA1Update(&context, data, size);
    SHA1Final(digest.data(), &context);
    return digest == expected;
}

PokemonWhiteAudioClass Classify(u16 seqId, u8 player) noexcept
{
    if (player >= 1 && player <= 5)
        return PokemonWhiteAudioClass::SFX;
    if (seqId >= 1300 && seqId <= 1331)
        return PokemonWhiteAudioClass::ME;
    if (player == 0 || player == 6)
        return PokemonWhiteAudioClass::BGM;
    return PokemonWhiteAudioClass::Unknown;
}

} // namespace

PokemonWhiteAudioClassifier::PokemonWhiteAudioClassifier(melonDS::NDS& nds) noexcept :
    NDS(nds)
{
}

void PokemonWhiteAudioClassifier::Initialize(const NDSCart::CartCommon* cart)
{
    Enabled = false;
    Cache.clear();
    ResetRuntime();

    if (!cart)
        return;

    const NDSHeader& header = cart->GetHeader();
    const u8* rom = cart->GetROM();
    const u32 romSize = cart->GetROMLength();

    if (!rom
        || romSize != ROMSize
        || std::memcmp(header.GameTitle, ExpectedTitle.data(), ExpectedTitle.size()) != 0
        || std::memcmp(header.GameCode, ExpectedGameCode.data(), ExpectedGameCode.size()) != 0
        || header.ROMVersion != 0)
        return;

    if (!SHA256Matches(rom, romSize, ExpectedROMSHA256))
        return;

    if (!IsRangeValid(header.ARM7ROMOffset, header.ARM7Size, romSize)
        || !SHA1Matches(rom + header.ARM7ROMOffset, header.ARM7Size, ExpectedARM7SHA1))
        return;

    if (!IsRangeValid(SDATOffset, SDATSize, romSize)
        || !SHA256Matches(rom + SDATOffset, SDATSize, ExpectedSDATSHA256))
        return;

    if (!BuildCache(rom + SDATOffset, SDATSize))
    {
        Cache.clear();
        return;
    }

    Enabled = true;
}

bool PokemonWhiteAudioClassifier::BuildCache(const u8* sdat, u32 size)
{
    if (size < 0x40 || std::memcmp(sdat, "SDAT", 4) != 0 || ReadLE32(sdat + 8) != size)
        return false;

    const u32 infoOffset = ReadLE32(sdat + 0x18);
    const u32 infoSize = ReadLE32(sdat + 0x1C);
    const u32 fatOffset = ReadLE32(sdat + 0x20);
    const u32 fatSize = ReadLE32(sdat + 0x24);

    if (!IsRangeValid(infoOffset, infoSize, size) || infoSize < 0x40
        || !IsRangeValid(fatOffset, fatSize, size) || fatSize < 12
        || std::memcmp(sdat + infoOffset, "INFO", 4) != 0
        || std::memcmp(sdat + fatOffset, "FAT ", 4) != 0)
        return false;

    const u32 seqRecordOffset = ReadLE32(sdat + infoOffset + 8);
    if (!IsRangeValid(seqRecordOffset, 4, infoSize))
        return false;
    const u32 seqRecord = infoOffset + seqRecordOffset;
    const u32 seqCount = ReadLE32(sdat + seqRecord);
    if (seqCount > 0x10000 || !IsRangeValid(seqRecord, 4 + seqCount * 4, size))
        return false;

    const u32 fileCount = ReadLE32(sdat + fatOffset + 8);
    if (fileCount > (fatSize - 12) / 16)
        return false;

    Cache.reserve(seqCount);
    for (u32 seqId = 0; seqId < seqCount; seqId++)
    {
        const u32 entryOffset = ReadLE32(sdat + seqRecord + 4 + seqId * 4);
        if (entryOffset == 0 || !IsRangeValid(entryOffset, 12, infoSize))
            continue;

        const u8* infoEntry = sdat + infoOffset + entryOffset;
        const u16 fileId = ReadLE16(infoEntry);
        if (fileId >= fileCount)
            continue;

        const u8* fatEntry = sdat + fatOffset + 12 + fileId * 16;
        const u32 fileOffset = ReadLE32(fatEntry);
        const u32 fatFileSize = ReadLE32(fatEntry + 4);
        if (!IsRangeValid(fileOffset, fatFileSize, size) || fatFileSize < 0x1C)
            continue;

        const u8* file = sdat + fileOffset;
        if (std::memcmp(file, "SSEQ", 4) != 0)
            continue;

        const u32 fileSize = ReadLE32(file + 8);
        const u32 dataOffset = ReadLE32(file + 0x18);
        if (fileSize < 0x1C || fileSize > fatFileSize || dataOffset >= fileSize)
            continue;

        const u8 player = infoEntry[9];
        Cache.push_back({
            file,
            fileSize,
            dataOffset,
            static_cast<u16>(seqId),
            player,
            Classify(static_cast<u16>(seqId), player),
        });
    }

    return !Cache.empty();
}

void PokemonWhiteAudioClassifier::ResetRuntime() noexcept
{
    const u32 gateState = AdvanceGateEpoch();
    Runtime.fill({});
    Pending.fill({});
    ResetGatePhases(gateState);
    ExChannelMainUpdate = 0;
}

u32 PokemonWhiteAudioClassifier::AdvanceGateEpoch() noexcept
{
    u32 state = GateState.load(std::memory_order_relaxed);
    while (true)
    {
        const u32 newState = NextGateState(state, GateStateDivisor(state));
        if (GateState.compare_exchange_weak(
                state, newState, std::memory_order_release, std::memory_order_relaxed))
            return newState;
    }
}

u32 PokemonWhiteAudioClassifier::PublishGateDivisor(u32 divisor) noexcept
{
    divisor = SanitizeGateDivisor(divisor);
    u32 state = GateState.load(std::memory_order_relaxed);
    while (GateStateDivisor(state) != divisor)
    {
        const u32 newState = NextGateState(state, divisor);
        if (GateState.compare_exchange_weak(
                state, newState, std::memory_order_release, std::memory_order_relaxed))
            return newState;
    }
    return state;
}

void PokemonWhiteAudioClassifier::SetBgmGateDivisor(u32 requested) noexcept
{
    static_cast<void>(PublishGateDivisor(requested));
}

void PokemonWhiteAudioClassifier::SynchronizeGatePhase(
    GatePhaseState& phase, u32 gateState) noexcept
{
    if (GateEpochChanged(phase.ObservedEpoch, gateState))
    {
        phase.Phase = GatePhaseAfterObservation(
            phase.ObservedEpoch, phase.Phase, gateState);
        phase.ObservedEpoch = GateStateEpoch(gateState);
    }
}

void PokemonWhiteAudioClassifier::ResetGatePhases(u32 gateState) noexcept
{
    for (GatePhaseState& phase : GatePhases)
    {
        phase.ObservedEpoch = GateStateEpoch(gateState);
        phase.Phase = 0;
    }
}

bool PokemonWhiteAudioClassifier::HandleSeqPlayerGate()
{
    const u32 gateState = GateState.load(std::memory_order_acquire);
    const u32 divisor = GateStateDivisor(gateState);
    if (divisor == 0 || NDS.ARM7.R[10] == 0)
        return false;

    const u32 playerAddress = NDS.ARM7.R[5];
    if (playerAddress < PlayerBase)
        return false;

    const u32 offset = playerAddress - PlayerBase;
    if ((offset % PlayerStride) != 0)
        return false;

    const u32 player = offset / PlayerStride;
    if (player >= Runtime.size())
        return false;

    GatePhaseState& gatePhase = GatePhases[player];
    SynchronizeGatePhase(gatePhase, gateState);

    const RuntimeSeqClassification& runtime = Runtime[player];
    if (!runtime.Active || runtime.Class != PokemonWhiteAudioClass::BGM)
        return false;

    gatePhase.Phase++;
    if (gatePhase.Phase < divisor)
        return true;

    gatePhase.Phase -= divisor;
    return false;
}

void PokemonWhiteAudioClassifier::HandleExChannelMain() noexcept
{
    ExChannelMainUpdate = NDS.ARM7.R[0];
}

bool PokemonWhiteAudioClassifier::ResolveExChannelOwner(
    u32 channel, u32& ownerPlayer) const
{
    if (channel >= ExChannelCount)
        return false;

    const u32 exChannel = ExChannelBase + channel * ExChannelStride;
    if (!(NDS.ARM7Read8(exChannel + 3) & 1)
        || NDS.ARM7Read32(exChannel + 0x48) != ExChannelReleaseAddress)
        return false;

    const u32 trackAddress = NDS.ARM7Read32(exChannel + 0x4C);
    if (trackAddress < TrackBase)
        return false;

    const u32 trackOffset = trackAddress - TrackBase;
    if ((trackOffset % TrackStride) != 0)
        return false;

    const u32 track = trackOffset / TrackStride;
    if (track >= TrackCount)
        return false;

    for (u32 player = 0; player < Runtime.size(); player++)
    {
        const RuntimeSeqClassification& runtime = Runtime[player];
        if (!runtime.Active || runtime.Class != PokemonWhiteAudioClass::BGM
            || !(NDS.ARM7Read8(PlayerBase + player * PlayerStride) & 1))
            continue;

        for (u32 slot = 0; slot < 16; slot++)
        {
            if (NDS.ARM7Read8(PlayerBase + player * PlayerStride + 8 + slot) == track)
            {
                ownerPlayer = player;
                return true;
            }
        }
    }

    return false;
}

void PokemonWhiteAudioClassifier::HandleExChannelLoop()
{
    const u32 gateState = GateState.load(std::memory_order_acquire);

    // SND_ExChannelMain keeps its update flag in r10. Restore it before every
    // channel because a gated BGM channel may have cleared it on the prior loop.
    NDS.ARM7.R[10] = ExChannelMainUpdate;

    const u32 channel = NDS.ARM7.R[5];
    if (channel >= ExChannelCount)
        return;

    if (GateStateDivisor(gateState) == 0 || ExChannelMainUpdate == 0)
        return;

    u32 ownerPlayer = 0;
    if (!ResolveExChannelOwner(channel, ownerPlayer))
        return;

    GatePhaseState& gatePhase = GatePhases[ownerPlayer];
    SynchronizeGatePhase(gatePhase, gateState);
    if (gatePhase.Phase != 0)
    {
        // update=0 preserves the current envelope/LFO/fade values while the
        // hardware channel and PCM sample playback continue normally.
        NDS.ARM7.R[10] = 0;
    }
}

const u8* PokemonWhiteAudioClassifier::GetGuestRange(u32 address, u32 size) const
{
    MemRegion region {};
    if (!NDS.ARM7GetMemRegion(address, false, &region) || !region.Mem)
        return nullptr;

    const u32 offset = address & region.Mask;
    if (size > region.Mask + 1 - offset)
        return nullptr;
    return region.Mem + offset;
}

const PokemonWhiteAudioClassifier::SSEQEntry* PokemonWhiteAudioClassifier::Resolve(
    u32 pointer, u32& matches) const
{
    matches = 0;
    const SSEQEntry* result = nullptr;

    for (const SSEQEntry& entry : Cache)
    {
        u32 fileAddress = pointer;
        const u8* header = GetGuestRange(fileAddress, 0x1C);
        if (!header || std::memcmp(header, "SSEQ", 4) != 0)
        {
            if (pointer < entry.DataOffset)
                continue;
            fileAddress = pointer - entry.DataOffset;
            header = GetGuestRange(fileAddress, 0x1C);
        }

        if (!header || std::memcmp(header, "SSEQ", 4) != 0
            || ReadLE32(header + 8) != entry.FileSize
            || ReadLE32(header + 0x18) != entry.DataOffset)
            continue;

        const u8* guestFile = GetGuestRange(fileAddress, entry.FileSize);
        if (!guestFile || std::memcmp(guestFile, entry.File, entry.FileSize) != 0)
            continue;

        result = &entry;
        matches++;
        if (matches > 1)
            result = nullptr;
    }

    return matches == 1 ? result : nullptr;
}

void PokemonWhiteAudioClassifier::ReceiveStart(u32 player, u32 pointer, u32 offset)
{
    if (player >= Runtime.size())
        return;

    GatePhases[player].Phase = 0;
    Pending[player] = {};
    Pending[player].Valid = true;
    Pending[player].Pointer = pointer;
    Pending[player].Offset = offset;

    u32 matches = 0;
    Pending[player].Entry = Resolve(pointer, matches);
    if (!Pending[player].Entry && matches == 0 && offset && pointer <= 0xFFFFFFFF - offset)
        Pending[player].Entry = Resolve(pointer + offset, matches);
}

void PokemonWhiteAudioClassifier::ClassifyPlayer(u32 player, bool usePending)
{
    if (player >= Runtime.size())
        return;

    GatePhases[player].Phase = 0;
    const PendingStart pending = Pending[player];
    if (usePending)
        Pending[player] = {};

    Runtime[player] = {};

    const u32 playerAddress = PlayerBase + player * PlayerStride;
    if (!(NDS.ARM7Read8(playerAddress) & 1))
        return;

    u32 pointer = 0;
    for (u32 slot = 0; slot < 16; slot++)
    {
        const u8 track = NDS.ARM7Read8(playerAddress + 8 + slot);
        if (track < TrackCount)
        {
            pointer = NDS.ARM7Read32(TrackBase + track * TrackStride + 0x24);
            if (pointer)
                break;
        }
    }

    Runtime[player].Active = true;

    u32 matches = 0;
    const SSEQEntry* entry = nullptr;
    const bool pendingOffsetMatches = pending.Offset <= 0xFFFFFFFF - pending.Pointer
        && pointer == pending.Pointer + pending.Offset;
    if (usePending && pending.Valid
        && (pointer == pending.Pointer || pendingOffsetMatches))
    {
        entry = pending.Entry;
    }
    else if (pointer)
        entry = Resolve(pointer, matches);

    if (entry)
    {
        Runtime[player].SeqId = entry->SeqId;
        Runtime[player].PlayerInfo = entry->PlayerInfo;
        Runtime[player].Class = entry->Class;
    }
}

void PokemonWhiteAudioClassifier::ClearPlayer(u32 player)
{
    if (player >= Runtime.size())
        return;

    GatePhases[player].Phase = 0;
    Pending[player] = {};
    Runtime[player] = {};
}

bool PokemonWhiteAudioClassifier::HandleARM7Hook(u32 address)
{
    if (!Enabled)
        return false;

    if (address == SeqPlayerGateAddress)
        return HandleSeqPlayerGate();

    if (address == ExChannelMainAddress)
    {
        HandleExChannelMain();
        return false;
    }
    if (address == ExChannelLoopAddress)
    {
        HandleExChannelLoop();
        return false;
    }
    if (address == StartFunctionAddress)
    {
        ReceiveStart(NDS.ARM7.R[0], NDS.ARM7.R[1], NDS.ARM7.R[2]);
    }
    else if (address == StartHookAddress)
    {
        ClassifyPlayer(NDS.ARM7.R[6], true);
    }
    else if (address == StopHookAddress)
    {
        const u32 playerAddress = NDS.ARM7.R[0];
        if (playerAddress >= PlayerBase)
        {
            const u32 offset = playerAddress - PlayerBase;
            if ((offset % PlayerStride) == 0 && offset / PlayerStride < Runtime.size())
                ClearPlayer(offset / PlayerStride);
        }
    }

    return false;
}

bool PokemonWhiteAudioJITHook(ARM* cpu, u32 address)
{
    return cpu->NDS.PokemonWhiteAudio.HandleARM7Hook(address);
}

void PokemonWhiteAudioClassifier::RebuildRuntime()
{
    const u32 gateState = AdvanceGateEpoch();
    Pending.fill({});
    Runtime.fill({});
    ResetGatePhases(gateState);
    ExChannelMainUpdate = 0;
    if (!Enabled)
        return;

    for (u32 player = 0; player < Runtime.size(); player++)
    {
        if (NDS.ARM7Read8(PlayerBase + player * PlayerStride) & 1)
            ClassifyPlayer(player);
    }
}

} // namespace melonDS
