#pragma once

#include <cstdint>

namespace siemens_mp377 {

constexpr uint32_t kErtec400PciSelect = 0x40007000u;

constexpr uint32_t kErtecBar0Base = 0xC5000000u;
constexpr uint32_t kErtecBar1Base = 0xC5010000u;
constexpr uint32_t kErtecBar2Base = 0xC5020000u;
constexpr uint32_t kErtecBar4Base = 0xC5030000u;
constexpr uint32_t kErtecBar5Base = 0xC5040000u;
constexpr uint32_t kErtecSmallBarsBase = kErtecBar0Base;
/* siemens_mp377_v1040 eddertec400.dll BAR mappings; ERTEC400 Manual V1.2.2,
   IRT register and communication-RAM aperture. */
constexpr uint32_t kErtecIrtApertureSize = 0x00200000u;
/* ERTEC400 Manual V1.2.2, memory map, BOOT ROM table: KRAM. */
constexpr uint32_t kErtecCommunicationRamBase = 0x00100000u;
constexpr uint32_t kErtecCommunicationRamSize = 0x00030000u;
constexpr uint32_t kErtecCommunicationRamEnd = kErtecCommunicationRamBase + kErtecCommunicationRamSize;
constexpr uint32_t kErtecSmallBarsEnd = kErtecSmallBarsBase + kErtecIrtApertureSize;

/* siemens_mp377_v1040 eddertec400.dll sub_28E1FE8 clears 0x2000 bytes
   starting at BAR2 and writes the eight-byte stop marker at BAR2+0x1FF8. */
constexpr uint32_t kErtecBar2RamOffset = kErtecBar2Base - kErtecSmallBarsBase;
constexpr uint32_t kErtecBar2RamSize = 0x00010000u;
constexpr uint32_t kErtecBar2RamEnd = kErtecBar2RamOffset + kErtecBar2RamSize;

constexpr uint32_t kErtecEddPhyModeOffset = 0x00019038u;
constexpr uint32_t kErtecEddHwTypeOffset = 0x00019400u;
constexpr uint32_t kErtecEddHwTypeErtec400Rev5 = 0x20050000u;

constexpr uint32_t kErtecResetControlOffset = 0x0001260Cu;
constexpr uint32_t kErtecBootReadyOffset = 0x00101020u;
constexpr uint32_t kErtecBootReadyBit = 0x00000001u;
constexpr uint32_t kErtecSwiControlOffset = kErtecEddPhyModeOffset;
constexpr uint32_t kErtecSwiStatusOffset = 0x00019404u;
constexpr uint32_t kErtecSwiStatusAllDone = 0x0000FFFFu;
constexpr uint32_t kErtecSwiStatusMinMode = 0x0000FFFAu;
/* eddertec400.dll sub_2912894 indexes its per-port switch-register table;
   TRACEInitComponent selects register type 0x0A for port zero, whose table
   entry is BAR3+0x0008. */
constexpr uint32_t kErtecSwiTraceControlBaseOffset = 0x00000008u;
/* Register type 0x06 in the same driver table; sub_2912894 writes one
   instance per hardware port. */
constexpr uint32_t kErtecSwiPortControlBaseOffset = 0x00000004u;
/* Register type 0x00 in the driver's per-port table. */
constexpr uint32_t kErtecSwiPortModeBaseOffset = 0x00000010u;
/* Register type 0x05 in the driver's per-port table. */
constexpr uint32_t kErtecSwiPortStateBaseOffset = 0x00000014u;
/* Register type 0x01 in the driver's per-port table. */
constexpr uint32_t kErtecSwiPortVlanBaseOffset = 0x0000000Cu;
constexpr uint32_t kErtecSwiPortStride = 0x00001000u;
constexpr uint32_t kErtecSwiPortCount = 4u;
/* Register type 0x02 in dword_28C5320, selected by sub_2912894. */
constexpr uint32_t kErtecSwiPhyControlBaseOffset = 0x00015440u;
/* Register type 0x07 in dword_28C5320, selected by sub_2912894. */
constexpr uint32_t kErtecSwiPhyStatusBaseOffset = 0x00015444u;
/* Register type 0x08 in dword_28C5320, selected by sub_2912894. */
constexpr uint32_t kErtecSwiPhyModeBaseOffset = 0x00015448u;
/* Register type 0x09 in dword_28C5320, selected by sub_2912894. */
constexpr uint32_t kErtecSwiPhyTimingBaseOffset = 0x00015450u;
constexpr uint32_t kErtecSwiPhyPortStride = 0x00000080u;
/* Register type 0x27 in dword_28C5320; the four ports occupy adjacent words. */
constexpr uint32_t kErtecSwiPortFilterBaseOffset = 0x00016048u;
constexpr uint32_t kErtecSwiPortFilterStride = 0x00000004u;
/* Register type 0x03 in dword_28C5320.  SwiPhyEnableLinkIRQ reads,
   modifies, and writes one command word for each port. */
constexpr uint32_t kErtecPhyCommandBaseOffset = 0x00015010u;
constexpr uint32_t kErtecPhyRegisterStride = 0x00000008u;
/* eddertec400.dll sub_290C4E8 (SERSetupxRT) initializes the four xRT
   padding words and the two station-address words. */
constexpr uint32_t kErtecXrtPaddingBaseOffset = 0x00019000u;
constexpr uint32_t kErtecXrtStationAddressHiOffset = 0x00019014u;
constexpr uint32_t kErtecXrtStationAddressLoOffset = 0x00019018u;
/* eddertec400.dll sub_290A638 (SERSetIRTSAdress). */
constexpr uint32_t kErtecIrtStationAddressHiOffset = 0x0001901Cu;
constexpr uint32_t kErtecIrtStationAddressLoOffset = 0x00019020u;
/* eddertec400.dll sub_290B574 (SERAcwSetup). */
constexpr uint32_t kErtecAcwBufferAddressOffset = 0x00019030u;
constexpr uint32_t kErtecAcwCountOffset = 0x00019034u;
/* eddertec400.dll sub_28DF96C configures these three IRQ controller words;
   the first is read/modify/write, the remaining two are programmed directly. */
constexpr uint32_t kErtecIrqControlOffset = 0x00017000u;
constexpr uint32_t kErtecIrqMaskLoOffset = 0x00017004u;
constexpr uint32_t kErtecIrqMaskHiOffset = 0x00017008u;
constexpr uint32_t kErtecConsistencyControlBaseOffset = 0x0000A000u;
constexpr uint32_t kErtecConsistencyControlEndOffset = kErtecConsistencyControlBaseOffset + 0x10u;
constexpr uint32_t kErtecIrtTimerBaseOffset = 0x0000B000u;
constexpr uint32_t kErtecIrtControlOffset = 0x00013000u;
constexpr uint32_t kErtecIrtStartOffset = 0x00018400u;
constexpr uint32_t kErtecFlowControlOffset = 0x00016410u;

/* siemens_mp377_v1040 eddertec400.dll ERTEC400_IST,
   sub_28DFF28/sub_28DFC54, event words +0x17418/+0x1741C. */
constexpr int kErtecIrqSource = 0x1A;
constexpr uint32_t kErtecIrqStatusLoOffset = 0x00017418u;
constexpr uint32_t kErtecIrqStatusHiOffset = 0x0001741Cu;
constexpr uint32_t kErtecIrqAckOffset = 0x00017420u;
/* eddertec400.dll sub_28E0258 (ERTEC400_IST) accumulates event words into
   these two read/write software-visible latches. */
constexpr uint32_t kErtecIrqAccumulatedLoOffset = 0x00017410u;
constexpr uint32_t kErtecIrqAccumulatedHiOffset = 0x00017414u;
constexpr uint32_t kErtecIrqLinkChangeHiBit = 0x00000200u;

constexpr uint32_t kErtecSerPrimCommandOffset = 0x00016400u;
constexpr uint32_t kErtecSerSecCommandOffset = 0x00016404u;
constexpr uint32_t kErtecSerConfCommandOffset = 0x00016408u;
constexpr uint32_t kErtecSerCommandActiveBit = 0x80000000u;
constexpr uint32_t kErtecSerCommandOkBit = 0x40000000u;
constexpr uint32_t kErtecSerFdbBaseOffset = 0x00016010u;
constexpr uint32_t kErtecSerFdbLastIndexOffset = 0x00016014u;
constexpr uint32_t kErtecSerFdbSearchLimitOffset = 0x0001601Cu;
constexpr uint32_t kErtecSerFdbReservedBit = 0x00000400u;
constexpr uint32_t kErtecSerFdbValidBit = 0x00000800u;
constexpr uint32_t kErtecSerResultMask = 0x003FFFFFu;
constexpr uint32_t kErtecSerNoFdbEntry = 0x001FFFFFu;

/* siemens_mp377_v1040 eddertec400.dll SERSetupNRT. */
constexpr uint32_t kErtecNrtDmacBaseOffset = 0x00012400u;
constexpr uint32_t kErtecNrtDmacStride = 0x0000000Cu;
constexpr uint32_t kErtecNrtDmacPortCount = 4u;

/* eddertec400.dll sub_2901C0C XPLL control words in the BAR1 register
   window.  The routine performs read/modify/write on these three words. */
constexpr uint32_t kErtecXpllPllOutControl0Offset = 0x00012500u;
constexpr uint32_t kErtecXpllPllOutControl1Offset = 0x00012504u;
constexpr uint32_t kErtecXpllPllControlOffset = 0x00012510u;

/* eddertec400.dll sub_29357B8 (TRACEInitComponent) programs the trace
   buffer address, buffer length, and entry count at BAR3+0x18000. */
constexpr uint32_t kErtecTraceBufferAddressOffset = 0x00018000u;
constexpr uint32_t kErtecTraceBufferLengthOffset = 0x00018004u;
constexpr uint32_t kErtecTraceEntryCountOffset = 0x00018008u;
/* eddertec400.dll sub_28F3F80 (EDDDeviceSetupSER) writes the detected-port
   bit mask before it configures the SER/KRAM state. */
constexpr uint32_t kErtecSerPortPresenceMaskOffset = 0x00010000u;

constexpr uint32_t kErtecSmallWindowBase = kErtecSmallBarsBase;
constexpr uint32_t kErtecSmallWindowEnd = kErtecSmallBarsEnd;
constexpr uint32_t kErtecSmallWindowSize = kErtecSmallWindowEnd - kErtecSmallWindowBase;

constexpr uint32_t kErtecBar3Base = 0xC5800000u;
constexpr uint32_t kErtecBar3Size = 0x00800000u;
constexpr uint32_t kErtecBar3End = kErtecBar3Base + kErtecBar3Size;
constexpr uint32_t kErtecBar3WindowBase = kErtecBar3Base;
constexpr uint32_t kErtecBar3WindowEnd = kErtecBar3End;
constexpr uint32_t kErtecBar3WindowSize = kErtecBar3WindowEnd - kErtecBar3WindowBase;

} /* namespace siemens_mp377 */
