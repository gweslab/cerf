#pragma once

#include "ite_it8368.h"

#include "../pcmcia/pcmcia_slot.h"
#include "../../core/service.h"

class IteIt8368SocketHost : public Service,
                            public PcmciaSlotHost,
                            public IteIt8368IntSink {
public:
    IteIt8368SocketHost(CerfEmulator& emu, const wchar_t* slot_name);

    void OnReady() override;
    void OnShutdown() override;

    void OnCardDetectChanged(PcmciaSlot&) override;
    void OnCardIrqAsserted(PcmciaSlot&) override;
    void OnCardIrqDeasserted(PcmciaSlot&) override;

protected:
    PcmciaSlot& Slot() { return slot0_; }

private:
    PcmciaSlot slot0_;
};
