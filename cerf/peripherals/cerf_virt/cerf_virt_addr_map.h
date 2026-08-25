#pragma once

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned int uint32_t;
#define CERF_VIRT_GUEST 1
#else
#include <cstdint>
#endif

namespace CerfVirt {

const uint32_t kBaseMagic = 0xCEF0BA5Eu;

const uint32_t kTotalSize = 0x10000000u;

const uint32_t kRegsOffset = 0u;
const uint32_t kRegsSize   = 0x10000u;

const uint32_t kTickProfilerOffset = 0x0000u;
const uint32_t kTickProfilerSize   = 0x1000u;

const uint32_t kFramebufferRegsOffset = 0x1000u;
const uint32_t kFramebufferRegsSize   = 0x1000u;

const uint32_t kGpeCmdOffset = 0x2000u;
const uint32_t kGpeCmdSize   = 0x1000u;

const uint32_t kPointerOffset = 0x3000u;
const uint32_t kPointerSize   = 0x1000u;

const uint32_t kCursorOffset = 0x4000u;
const uint32_t kCursorSize   = 0x1000u;

const uint32_t kFolderShareOffset = 0x5000u;
const uint32_t kFolderShareSize   = 0x1000u;

const uint32_t kResizeOffset = 0x6000u;
const uint32_t kResizeSize   = 0x1000u;

const uint32_t kLogChannelOffset = 0x7000u;
const uint32_t kLogChannelStride = 0x1000u;
const uint32_t kLogChannelIdStub          = 0u;
const uint32_t kLogChannelIdDisplay       = 1u;
const uint32_t kLogChannelIdSharedFolders = 2u;
const uint32_t kLogChannelCount  = 3u;
const uint32_t kLogChannelSize   = kLogChannelCount * kLogChannelStride;
const uint32_t kLogChannelTxSlot    = 0x000u;
const uint32_t kLogChannelFatalSlot = 0x800u;

const uint32_t kTaskManagerOffset = 0xA000u;
const uint32_t kTaskManagerSize   = 0x1000u;

const uint32_t kKeyboardOffset = 0xB000u;
const uint32_t kKeyboardSize   = 0x1000u;

const uint32_t kPaletteOffset  = 0xC000u;
const uint32_t kPaletteSize    = 0x1000u;
const uint32_t kPaletteEntries = 256u;

const uint32_t kArenaCtlOffset = 0xD000u;
const uint32_t kArenaCtlSize   = 0x1000u;
const uint32_t kArenaCtlClaimPid  = 0x000u;

const uint32_t kCalibSignalOffset = 0xE000u;
const uint32_t kCalibSignalSize   = 0x1000u;

const uint32_t kColorSchemeOffset = 0xF000u;
const uint32_t kColorSchemeSize   = 0x1000u;
const uint32_t kColorSchemeMax    = 30u;

const uint32_t kFramebufferMemOffset = 0x00100000u;
const uint32_t kFramebufferMemSize   = 0x02000000u;

const uint32_t kGuestBodyOffset  = kRegsSize;
const uint32_t kGuestBodyHdrSize = 0x1000u;

const uint32_t kInjectionBandSize   = 0x10000u;
const uint32_t kInjectionBandOffset = kFramebufferMemOffset - kInjectionBandSize;

const uint32_t kGuestBodyMaxSize = kInjectionBandOffset - kGuestBodyOffset;

const uint32_t kDmaArenaOffset   = kFramebufferMemOffset + kFramebufferMemSize;
const uint32_t kDmaArenaProcMax  = 8u;
const uint32_t kDmaPartitionSize = 0x00080000u;
const uint32_t kDmaArenaSize     = kDmaArenaProcMax * kDmaPartitionSize;

const uint32_t kFsStageOffset = kDmaArenaOffset + kDmaArenaSize;
const uint32_t kFsStagePbOff  = 0x0000u;
const uint32_t kFsStageIoOff  = 0x1000u;
const uint32_t kFsStageIoSize = 0x10000u;
const uint32_t kFsStageSize   = kFsStageIoOff + kFsStageIoSize;

const uint32_t kCurStageOffset = kFsStageOffset + kFsStageSize;
const uint32_t kCurStageSize   = 0x1000u;

const uint32_t kDmaPartOwnerPid    = 0x0Cu;
const uint32_t kDmaPartHdrSize     = 0x40u;

}

#ifdef CERF_VIRT_GUEST
extern volatile unsigned long g_CerfVirtBase;
#endif
