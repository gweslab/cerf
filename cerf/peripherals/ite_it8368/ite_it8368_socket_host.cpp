#include "ite_it8368_socket_host.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/pr31x00/pr31x00_card_space.h"

IteIt8368SocketHost::IteIt8368SocketHost(CerfEmulator& emu, const wchar_t* slot_name)
    : Service(emu), slot0_(emu, *this, slot_name) {}

void IteIt8368SocketHost::OnReady() {
    emu_.Get<Pr31x00CardSpace>().ProvideSockets(&slot0_, nullptr);
    emu_.Get<IteIt8368>().SetSlot(&slot0_);
    emu_.Get<IteIt8368>().SetIntSink(this);
    emu_.Get<HostWidgetRegistry>().Register(&slot0_);
}

void IteIt8368SocketHost::OnShutdown() { slot0_.OnShutdown(); }

void IteIt8368SocketHost::OnCardDetectChanged(PcmciaSlot&) {
    emu_.Get<IteIt8368>().NotifyCardDetect();
}

void IteIt8368SocketHost::OnCardIrqAsserted(PcmciaSlot&) {
    emu_.Get<IteIt8368>().SetCardIrq(true);
}

void IteIt8368SocketHost::OnCardIrqDeasserted(PcmciaSlot&) {
    emu_.Get<IteIt8368>().SetCardIrq(false);
}
