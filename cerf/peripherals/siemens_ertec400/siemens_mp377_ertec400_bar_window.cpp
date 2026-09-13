#include "siemens_mp377_ertec400_bar_window.h"

#include "siemens_mp377_ertec400.h"
#include "siemens_mp377_ertec400_model.h"
#include "siemens_mp377_ertec400_nrt.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

bool IsBar3(uint32_t address) {
    return address >= siemens_mp377::kErtecBar3Base && address < siemens_mp377::kErtecBar3End;
}

bool IsSmallIrtWindow(uint32_t address) {
    return address >= siemens_mp377::kErtecSmallBarsBase && address < siemens_mp377::kErtecSmallBarsEnd;
}

uint32_t ErtecIrtOffset(uint32_t address) {
    using namespace siemens_mp377;
    if (IsBar3(address)) {
        const uint32_t raw = address - kErtecBar3Base;
        /* ERTEC400 manual, memory section. */
        return raw < 0x00600000u ? raw % kErtecIrtApertureSize : 0xFFFFFFFFu;
    }
    if (IsSmallIrtWindow(address)) return address - kErtecSmallBarsBase;
    return 0xFFFFFFFFu;
}

uint32_t ErtecRegisterOffset(uint32_t address) {
    const uint32_t offset = ErtecIrtOffset(address);
    if (!IsSmallIrtWindow(address) || offset < 0x00100000u) return offset;
    const uint32_t aliased = offset - 0x00100000u;
    if (SiemensMp377Ertec400Model::IsReadableRegister(aliased) ||
        SiemensMp377Ertec400Model::IsWritableRegister(aliased)) return aliased;
    return offset;
}

bool IsIrtCommandLatch(uint32_t offset) {
    using namespace siemens_mp377;
    return offset == kErtecIrtControlOffset || offset == kErtecIrtControlOffset + 0x04u || offset == 0x00013048u ||
           offset == 0x00013404u;
}

bool IsCommunicationRam(uint32_t offset) {
    return offset >= siemens_mp377::kErtecCommunicationRamBase && offset < siemens_mp377::kErtecCommunicationRamEnd;
}

bool IsBar2Ram(uint32_t offset) {
    return offset >= siemens_mp377::kErtecBar2RamOffset && offset < siemens_mp377::kErtecBar2RamEnd;
}

bool IsReadOnlyLinkStatus(uint32_t offset) {
    return offset == 0x0001500Cu || offset == 0x00015014u || offset == 0x0001501Cu;
}

} // namespace

bool SiemensMp377Ertec400BarWindow::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Ertec400BarWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t SiemensMp377Ertec400BarWindow::ReadByte(uint32_t address) {
    const uint32_t word = ReadWord(address & ~3u);
    return static_cast<uint8_t>((word >> ((address & 3u) * 8u)) & 0xFFu);
}

uint16_t SiemensMp377Ertec400BarWindow::ReadHalf(uint32_t address) {
    const uint32_t word = ReadWord(address & ~3u);
    return static_cast<uint16_t>((word >> ((address & 2u) * 8u)) & 0xFFFFu);
}

uint32_t SiemensMp377Ertec400BarWindow::ReadWord(uint32_t address) {
    auto& model = emu_.Get<SiemensMp377Ertec400Model>();
    model.BeginAccess();
    const uint32_t offset = ErtecRegisterOffset(address);
    if (offset == 0xFFFFFFFFu) HaltUnsupportedAccess("ERTEC400 read outside IRT aperture", address, 0);
    uint32_t value = 0;
    if (IsCommunicationRam(offset) || IsBar2Ram(offset)) return model.GetWord(offset, value) ? value : 0u;
    if (!SiemensMp377Ertec400Model::IsReadableRegister(offset))
        HaltUnsupportedAccess("ERTEC400 read unmodelled register", address, offset);
    if (offset == siemens_mp377::kErtecEddHwTypeOffset) return siemens_mp377::kErtecEddHwTypeErtec400Rev5;
    if (IsReadOnlyLinkStatus(offset)) return model.DefaultRead(offset);
    if (offset == siemens_mp377::kErtecIrqStatusHiOffset)
        return emu_.Get<SiemensMp377Ertec400Nrt>().InterruptStatusHigh();
    if (offset == siemens_mp377::kErtecIrqStatusLoOffset) return model.DefaultRead(offset);
    if (offset == siemens_mp377::kErtecSerPrimCommandOffset && model.ConsumePrimaryReadback(value)) return value;
    if (offset == siemens_mp377::kErtecSerSecCommandOffset && model.ConsumeSecondaryReadback(value)) return value;
    if (offset == siemens_mp377::kErtecSerConfCommandOffset && model.GetWord(offset, value)) return value;
    if (offset == 0x00011414u) return model.FreeRunningCounter10ns();
    if (offset == siemens_mp377::kErtecIrtStartOffset) return model.IrtStartTime();
    if (offset == 0x0001640Cu) return model.SwitchPortControl();
    if (offset == 0x00011400u) return model.CyclicCounterLow();
    if (offset == 0x00011418u) return model.CyclicCounterHigh();
    if (offset == 0x0001102Cu) return model.CyclicCounterIncrement();
    if (offset == 0x00019010u) return model.CyclicControl();
    if (offset == 0x00016024u) return model.MulticastPortMask();
    const bool nrt_readback = SiemensMp377Ertec400Model::IsNrtDmacCommand(offset) ||
                              SiemensMp377Ertec400Model::IsNrtDmacAddress(offset);
    if (nrt_readback && model.GetWord(offset, value)) {
        if (SiemensMp377Ertec400Model::IsNrtDmacCommand(offset)) return value & ~0x00000002u;
        return value;
    }
    if (model.GetWord(offset, value)) return value;
    value = model.DefaultRead(offset);
    if (offset == siemens_mp377::kErtecSwiStatusOffset || offset == siemens_mp377::kErtecSwiControlOffset ||
        offset == siemens_mp377::kErtecSerPrimCommandOffset || offset == siemens_mp377::kErtecSerSecCommandOffset ||
        offset == siemens_mp377::kErtecSerConfCommandOffset || offset == siemens_mp377::kErtecIrtControlOffset ||
        offset == siemens_mp377::kErtecIrtControlOffset + 0x04u || offset == 0x00015000u || offset == 0x00015004u)
        model.SetWord(offset, value);
    return value;
}

void SiemensMp377Ertec400BarWindow::WriteByte(uint32_t address, uint8_t value) {
    const uint32_t aligned = address & ~3u;
    const uint32_t shift = (address & 3u) * 8u;
    const uint32_t mask = 0xFFu << shift;
    WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
}

void SiemensMp377Ertec400BarWindow::WriteHalf(uint32_t address, uint16_t value) {
    const uint32_t aligned = address & ~3u;
    const uint32_t shift = (address & 2u) * 8u;
    const uint32_t mask = 0xFFFFu << shift;
    WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
}

void SiemensMp377Ertec400BarWindow::WriteWord(uint32_t address, uint32_t value) {
    auto& model = emu_.Get<SiemensMp377Ertec400Model>();
    model.BeginAccess();
    const uint32_t raw_offset = ErtecIrtOffset(address);
    const uint32_t offset = ErtecRegisterOffset(address);
    if (offset == 0xFFFFFFFFu) HaltUnsupportedAccess("ERTEC400 write outside IRT aperture", address, value);
    if (raw_offset != offset && IsCommunicationRam(raw_offset) && value == 0xFFFFFFFFu) {
        model.SetWord(raw_offset, value);
        return;
    }
    if (IsCommunicationRam(offset) || IsBar2Ram(offset)) {
        model.SetWord(offset, value);
        return;
    }
    if (!SiemensMp377Ertec400Model::IsWritableRegister(offset))
        HaltUnsupportedAccess("ERTEC400 write unmodelled register", address, value);
    if (offset == siemens_mp377::kErtecEddHwTypeOffset || IsReadOnlyLinkStatus(offset) || offset == 0x00011414u ||
        offset == siemens_mp377::kErtecIrqStatusLoOffset || offset == siemens_mp377::kErtecIrqStatusHiOffset) {
        /* siemens_mp377_v1040 eddertec400.dll sub_28E6E3C. */
        if (value == 0xFFFFFFFFu) return;
        HaltUnsupportedAccess("ERTEC400 unexpected write to read-only register", address, value);
    }
    if (offset == siemens_mp377::kErtecResetControlOffset) {
        if ((value & 0x00000002u) != 0u) {
            /* ERTEC 400 Manual V1.2.2, RES_CTRL_REG. */
            model.Reset();
            emu_.Get<SiemensMp377Ertec400Nrt>().Reset();
        } else {
            model.SetWord(offset, value);
        }
        return;
    }
    if (offset == siemens_mp377::kErtecSwiControlOffset) { model.ApplySwitchControl(value); return; }
    if (offset == siemens_mp377::kErtecSwiStatusOffset) { model.PublishSwitchReady(value); return; }
    if (offset == siemens_mp377::kErtecIrqAckOffset) {
        model.SetWord(offset, value);
        emu_.Get<SiemensMp377Ertec400Nrt>().AcknowledgeInterrupt();
        return;
    }
    if (offset == siemens_mp377::kErtecIrqMaskHiOffset) {
        model.SetWord(offset, value);
        emu_.Get<SiemensMp377Ertec400Nrt>().SetInterruptMaskHigh(value);
        return;
    }
    if (offset == 0x00015004u) { model.WriteMdioControl(value); return; }
    if (offset == 0x00015000u) { model.SetWord(offset, value & 0x0000FFFFu); return; }
    if (offset == siemens_mp377::kErtecSerPrimCommandOffset) { model.CompletePrimaryCommand(value); return; }
    if (offset == siemens_mp377::kErtecSerSecCommandOffset) { model.CompleteSecondaryCommand(value); return; }
    if (offset == siemens_mp377::kErtecSerConfCommandOffset) {
        model.SetWord(offset, value & ~siemens_mp377::kErtecSerCommandActiveBit);
        return;
    }
    if (offset == siemens_mp377::kErtecIrtStartOffset) { model.WriteIrtStartTime(value); return; }
    if (offset == siemens_mp377::kErtecIrtStartOffset + 4u) { model.WriteIrtStartCommand(value); return; }
    if (offset == 0x0001640Cu) { model.WriteSwitchPortControl(value); return; }
    if (offset == 0x00011400u) { model.WriteCyclicCounterLow(value); return; }
    if (offset == 0x00011418u) { model.WriteCyclicCounterHigh(value); return; }
    if (offset == 0x0001102Cu) { model.WriteCyclicCounterIncrement(value); return; }
    if (offset == 0x00019010u) { model.WriteCyclicControl(value); return; }
    if (offset == 0x00016024u) { model.WriteMulticastPortMask(value); return; }
    if (offset == siemens_mp377::kErtecXpllPllOutControl0Offset ||
        offset == siemens_mp377::kErtecXpllPllOutControl1Offset ||
        offset == siemens_mp377::kErtecXpllPllControlOffset) {
        model.SetWord(offset, value);
        return;
    }
    if (offset >= siemens_mp377::kErtecConsistencyControlBaseOffset &&
        offset < siemens_mp377::kErtecConsistencyControlEndOffset && (offset & 3u) == 0u) {
        model.SetWord(offset, value);
        return;
    }
    if (IsIrtCommandLatch(offset)) { model.SetWord(offset, 0u); return; }
    if (SiemensMp377Ertec400Model::IsNrtDmacCommand(offset)) {
        model.SetWord(offset, value & ~0x00000002u);
        const uint32_t channel =
            (offset - siemens_mp377::kErtecNrtDmacBaseOffset) / siemens_mp377::kErtecNrtDmacStride;
        emu_.Get<SiemensMp377Ertec400Nrt>().ExecuteCommand(channel, value);
        return;
    }
    if (SiemensMp377Ertec400Model::IsNrtDmacAddress(offset)) {
        model.SetWord(offset, value);
        const uint32_t relative = offset - siemens_mp377::kErtecNrtDmacBaseOffset;
        const uint32_t channel = relative / siemens_mp377::kErtecNrtDmacStride;
        const bool receive = relative % siemens_mp377::kErtecNrtDmacStride == 8u;
        emu_.Get<SiemensMp377Ertec400Nrt>().ConfigureRingAddress(channel, receive, value);
        return;
    }
    if (SiemensMp377Ertec400Model::IsReadableRegister(offset) &&
        SiemensMp377Ertec400Model::IsWritableRegister(offset)) {
        model.SetWord(offset, value);
        return;
    }
    if (SiemensMp377Ertec400Model::IsWriteOnlyRegister(offset)) { model.SetWord(offset, value); return; }
    HaltUnsupportedAccess("ERTEC400 write lacks explicit semantics", address, value);
}
