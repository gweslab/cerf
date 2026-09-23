#include "cerf_virt_addr_map.h"
#include "cerf_guest_liveness.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../boot/guest_additions_binaries.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kPageMask = 0xFFFu;

class CerfVirtGuestBody : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        LoadBody();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase()
             + CerfVirt::kGuestBodyOffset;
    }
    uint32_t MmioSize() const override {
        const uint32_t body =
            (static_cast<uint32_t>(body_.size()) + kPageMask) & ~kPageMask;
        return CerfVirt::kGuestBodyHdrSize + body;
    }

    FastReadFn  FastReader() override { return &FastReadThunk;  }
    FastWriteFn FastWriter() override { return &FastWriteThunk; }

    void SaveState(StateWriter& w) override {
        emu_.Get<CerfGuestLiveness>().SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        emu_.Get<CerfGuestLiveness>().RestoreState(r);
    }

private:
    void LoadBody() {
        const std::string path = emu_.Get<GuestAdditionsBinaries>().BodyPath();
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) {
            LOG(Caution, "guest body: cannot open %s - cerf_guest.dll must be "
                    "built and staged before boot\n", path.c_str());
            CerfFatalExit();
        }
        const std::streamoff sz = f.tellg();
        body_.resize(static_cast<size_t>(sz));
        f.seekg(0);
        f.read(reinterpret_cast<char*>(body_.data()), sz);

        emu_.Get<GuestAdditionsBinaries>().StampWindowBase(body_);

        const uint32_t need = MmioSize();
        if (need > CerfVirt::kGuestBodyMaxSize) {
            LOG(Caution, "guest body: %s needs 0x%X bytes but the body window "
                    "is only 0x%X (0x%08X..0x%08X) - raise kFramebufferMemOffset "
                    "in cerf_virt_addr_map.h\n",
                path.c_str(), need, CerfVirt::kGuestBodyMaxSize,
                MmioBase(),
                MmioBase() + CerfVirt::kGuestBodyMaxSize);
            CerfFatalExit();
        }
        LOG(GuestAdditions, "guest body: serving %s (%zu bytes) at PA 0x%08X\n",
            path.c_str(), body_.size(), MmioBase());
    }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width_bytes) {
        auto* self = static_cast<CerfVirtGuestBody*>(ctx);
        self->emu_.Get<CerfGuestLiveness>().NotifyBodyFetch();
        if (off < CerfVirt::kGuestBodyHdrSize)
            return (off == 0) ? static_cast<uint32_t>(self->body_.size()) : 0u;
        const size_t boff = off - CerfVirt::kGuestBodyHdrSize;
        const size_t size = self->body_.size();
        uint8_t word[4] = {};
        if (boff < size)
            std::memcpy(word, self->body_.data() + boff, std::min<size_t>(width_bytes, size - boff));
        return static_cast<uint32_t>(cerf::le::UN(word, width_bytes));
    }

    static void FastWriteThunk(void*, uint32_t, uint32_t, uint32_t) {}

    std::vector<uint8_t> body_;
};

REGISTER_SERVICE(CerfVirtGuestBody);

}
