#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuPrimarySm501FbBridge : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;

    uint32_t MmioBase() const override { return kAtuPrimarySm501FbBase; }
    uint32_t MmioSize() const override { return siemens_mp377::kSm501FbBytes; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        const uint8_t value = emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().ReadByte(bus);
        return value;
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        const uint16_t value = emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().ReadHalf(bus);
        return value;
    }
    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        const uint32_t value = emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().ReadWord(bus);
        return value;
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().WriteByte(bus, value);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().WriteHalf(bus, value);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t bus = AtuPrimarySm501FbBusAddr(addr);
        emu_.Get<siemens_mp377::SiemensMp377Sm501Fb>().WriteWord(bus, value);
    }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuPrimarySm501FbBridge);
