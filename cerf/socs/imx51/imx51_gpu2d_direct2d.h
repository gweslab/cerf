#pragma once

#include "../../core/service.h"

#include <cstdint>

struct Gpu2dCopySpec;

/* The g12 direct-2D BitBlt engine: decodes a solid rect fill or a SCOORD1
   source->dest rect copy from the g12 register file (a render path distinct from
   the VGV2 polygon rasterizer) and drives the rasterizer's pixel writers. Reads
   the register file the command engine owns; holds no state of its own. */
class Imx51Gpu2dDirect2d : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    /* Solid rect fill under G2D_INPUT 0x01/0x09 (fires on the G2D_COLOR latch). */
    void Fill(const uint32_t (&regs)[0x100]);
    /* SCOORD1 source->dest rect copy under G2D_INPUT 0x00/0x02 (fires on the G2D_SXY
       write); `sxy` is the transient trigger value (source origin). */
    void Copy(const uint32_t (&regs)[0x100], uint32_t sxy);

private:
    /* Gates shared by Fill and Copy (ALPHABLEND/ROP/gradient/MASK/dest
       format/BASE0); each op adds its own distinct gates on top. */
    void CheckCommonGates(const uint32_t (&regs)[0x100]) const;
    /* Byte-identical fmt7->fmt7 rect copy (SCOORD1 source-sample), dest-clipped. */
    void CopyRect(const Gpu2dCopySpec& c);
    void UnpremultiplyRect(const Gpu2dCopySpec& c);
    [[noreturn]] void Halt(const uint32_t (&regs)[0x100], const char* why,
                           uint32_t addr, uint32_t data) const;
};
