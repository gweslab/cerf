#pragma once

#include "../../core/service.h"

#include <cstdint>

class StateWriter;
class StateReader;

/* The g12 VGV3 command-stream engine: walks the DMA command buffer from the armed
   cursor (pausing at the kick's MARKADD mark budget), decodes WRITE/DIRECT commands
   into the internal register file, accumulates path geometry, and dispatches grounded
   fills to the rasterizer + direct-2D engine at FLUSH/SXY/COLOR. */
class Imx51Gpu2dCommandEngine : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    /* Internal 2D/VG register write (command-window funnel word2). A non-zero CONTROL
       write kicks the stream walk (returns true when a submit retires); every other
       write stores or dispatches the register. */
    bool WriteReg(uint32_t addr, uint32_t data);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
    void PowerOnReset();

private:
    [[noreturn]] void Halt(const char* why, uint32_t addr, uint32_t data) const;
    bool     ProcessVgv3Stream(uint32_t mark_budget);
    void     ExecPacket(uint32_t base, uint32_t count);
    uint32_t ExecGeometry(uint32_t action, uint32_t addr, uint32_t fmt, uint32_t cnt,
                          uint32_t loop, uint32_t data_pa);
    void     EmitPoint(uint32_t action);
    /* Flatten a quadratic bezier C1(current)->C3(control)->C4(end) to device LineTos. */
    void     EmitQuad(float c3x, float c3y, float c4x, float c4y);
    void     DevicePoint(float px, float py, float& dx, float& dy) const;
    void     StoreReg(uint32_t reg, uint32_t data);
    static bool IsConsumedConfigReg(uint32_t reg);
    uint32_t ReadPa(uint32_t pa);
    void     FlushPath();

    uint32_t vgv3_nextaddr_  = 0;  /* NEXTADDR/CALLADDR register (armed by the stream) */
    uint32_t vgv3_nextcmd_   = 0;  /* NEXTCMD register (op/count/MARK/callcount) */
    uint32_t vgv3_cursor_    = 0;  /* persistent walk read pointer (survives a pause) */
    float    cur_x_          = 0.0f;  /* C4 current point, raw path coords */
    float    cur_y_          = 0.0f;
    bool     bbox_live_      = false;  /* VGV2_BBOX written; FLUSH superset gate applies */
    uint32_t vg_regs_[0x100] = {};  /* g12 config/geometry register file */
};
