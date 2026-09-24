#include "siemens_mp377_aspc2.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"
#include "../../state/state_stream.h"

namespace siemens_mp377 {

bool SiemensMp377Aspc2::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::SiemensMp377;
}

void SiemensMp377Aspc2::OnReady() {
    /* Siemens ASPC 2 Hardware User Description V1.0, ASIC Interface and
       Internal Registers; siemens_mp377_v1040 S7pbhmix.dll sub_2A530D0. */
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t SiemensMp377Aspc2::MmioBase() const {
    return kMp377Aspc2Base;
}
uint32_t SiemensMp377Aspc2::MmioSize() const {
    return kMp377Aspc2Size;
}

uint8_t SiemensMp377Aspc2::ReadByte(uint32_t addr) {
    const uint32_t offset = addr - MmioBase();
    if (offset == kVersionOffset) return kE2PlusVersion;
    if (offset == kMode0Offset) return mode0_;
    /* S7pbhmix.dll sub_2A52B30 reads these event/status bytes while its IST
       is idle.  No PROFIBUS peer is attached, so no event is pending. */
    if (offset == kInterruptEventLoOffset) return interrupt_event_lo_;
    if (offset == kInterruptEventHiOffset) return interrupt_event_hi_;
    if (offset == kInterruptStatusLoOffset || offset == kInterruptStatusHiOffset || offset == kAdditionalStatusOffset)
        return 0u;
    emu_.Get<Fatal>().Die("[MP377 ASPC2] read of unmodelled byte offset 0x%X", offset);
}

uint16_t SiemensMp377Aspc2::ReadHalf(uint32_t addr) {
    emu_.Get<Fatal>().Die("[MP377 ASPC2] read of unmodelled halfword offset 0x%X", addr - MmioBase());
}

uint32_t SiemensMp377Aspc2::ReadWord(uint32_t addr) {
    emu_.Get<Fatal>().Die("[MP377 ASPC2] read of unmodelled word offset 0x%X", addr - MmioBase());
}

void SiemensMp377Aspc2::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t offset = addr - MmioBase();
    if (offset == kInterruptMaskLoOffset) {
        /* S7pbhmix.dll sub_2A6A06C programs both interrupt mask bytes before
           it posts the request to ASPC2. */
        interrupt_mask_lo_ = value;
        return;
    }
    if (offset == kServiceControlLoOffset) {
        /* S7pbhmix.dll sub_2A530B8 programs the two service-control bytes. */
        service_control_lo_ = value;
        return;
    }
    if (offset == kServiceControlHiOffset) {
        service_control_hi_ = value;
        return;
    }
    if (offset == kInterruptEventLoOffset) {
        /* S7pbhmix.dll sub_2A53254 restores the two event bytes from its
           saved ASPC2 state. */
        interrupt_event_lo_ = value;
        return;
    }
    if (offset == kInterruptEventHiOffset) {
        interrupt_event_hi_ = value;
        return;
    }
    if (offset == kMode0Offset) {
        /* ASPC2 Hardware User Description R1.0, table 5: mode register 0.
           S7pbhmix.dll sub_2A53254 clears bit zero during shutdown/reset. */
        mode0_ = value;
        return;
    }
    if (offset == kInterruptMaskHiOffset) {
        interrupt_mask_hi_ = value;
        return;
    }
    if (offset == kRequestControlOffset) {
        /* S7pbhmix.dll sub_2A6A06C ORs the request byte with 0x3F and
           commits it here after programming the interrupt masks. */
        request_control_ = value;
        return;
    }
    if (offset == kProbeControlOffset) {
        /* S7pbhmix.dll sub_2A530D0 brackets the release-status read with
           0x40/0x00; sub_2A60990 later programs the generated interface
           address byte through the same board-interface register. */
        probe_control_ = value;
        return;
    }
    if (offset == kInterfaceAddressOffset) {
        /* S7pbhmix.dll sub_2A60990 writes the generated interface address. */
        interface_address_ = value;
        return;
    }
    if (offset == kInterruptControlLoOffset) {
        interrupt_control_lo_ = value;
        return;
    }
    if (offset == kVersionOffset) {
        /* The register is command-on-write and release-status-on-read in
           S7pbhmix.dll sub_2A5318C/sub_2A52B30. */
        interrupt_control_hi_ = value;
        return;
    }
    emu_.Get<Fatal>().Die("[MP377 ASPC2] write of unmodelled byte offset 0x%X = 0x%02X", offset, value);
}

void SiemensMp377Aspc2::WriteHalf(uint32_t addr, uint16_t value) {
    emu_.Get<Fatal>().Die("[MP377 ASPC2] write of unmodelled halfword offset 0x%X = 0x%04X", addr - MmioBase(), value);
}

void SiemensMp377Aspc2::WriteWord(uint32_t addr, uint32_t value) {
    emu_.Get<Fatal>().Die("[MP377 ASPC2] write of unmodelled word offset 0x%X = 0x%08X", addr - MmioBase(), value);
}

void SiemensMp377Aspc2::SaveState(StateWriter& w) {
    w.Write("probe_control", probe_control_);
    w.Write("interrupt_control_lo", interrupt_control_lo_);
    w.Write("interrupt_control_hi", interrupt_control_hi_);
    w.Write("interrupt_mask_lo", interrupt_mask_lo_);
    w.Write("interrupt_mask_hi", interrupt_mask_hi_);
    w.Write("request_control", request_control_);
    w.Write("mode0", mode0_);
    w.Write("interrupt_event_lo", interrupt_event_lo_);
    w.Write("interrupt_event_hi", interrupt_event_hi_);
    w.Write("interface_address", interface_address_);
    w.Write("service_control_lo", service_control_lo_);
    w.Write("service_control_hi", service_control_hi_);
}

void SiemensMp377Aspc2::RestoreState(StateReader& r) {
    r.Read("probe_control", probe_control_);
    r.Read("interrupt_control_lo", interrupt_control_lo_);
    r.Read("interrupt_control_hi", interrupt_control_hi_);
    r.Read("interrupt_mask_lo", interrupt_mask_lo_);
    r.Read("interrupt_mask_hi", interrupt_mask_hi_);
    r.Read("request_control", request_control_);
    r.Read("mode0", mode0_);
    r.Read("interrupt_event_lo", interrupt_event_lo_);
    r.Read("interrupt_event_hi", interrupt_event_hi_);
    r.Read("interface_address", interface_address_);
    r.Read("service_control_lo", service_control_lo_);
    r.Read("service_control_hi", service_control_hi_);
}

REGISTER_SERVICE(SiemensMp377Aspc2);

} // namespace siemens_mp377
