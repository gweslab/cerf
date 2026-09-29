#pragma once

#include <cstdint>

class CerfEmulator;
class StateReader;
class StateWriter;

class Vr41xxPiuConverter {
public:
    explicit Vr41xxPiuConverter(CerfEmulator& emu) : emu_(emu) {}

    int  ConvertCoordinates(uint16_t pos_x, uint16_t pos_y);
    bool ConvertCommand(uint16_t cmd, uint16_t pos_x, uint16_t pos_y);
    bool ScanAdPorts(uint16_t ascn, uint16_t amsk);

    void InvalidatePage(int page);
    void InvalidateAdBuffer();

    bool ReadBuffer(uint32_t off, uint16_t* value) const;
    bool WriteBuffer(uint32_t off, uint16_t value);

    void Reset();
    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    CerfEmulator& emu_;
    uint16_t      page_buf_[2][5] = {};
    uint16_t      next_page_      = 0;
    uint16_t      adbuf_[4]       = {};
};
