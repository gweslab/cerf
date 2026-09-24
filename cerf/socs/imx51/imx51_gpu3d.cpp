#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "imx51_gpu3d_blit.h"
#include "imx51_gpu3d_draw.h"
#include "imx51_gpu3d_raster.h"
#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_regs.h"
#include "imx51_gpu3d_packet.h"
#include "imx51_gpu3d_context.h"

#include <cstdint>
#include <cstring>
#include <unordered_map>

namespace {

using namespace imx51_gpu3d_regs;

class Imx51Gpu3d : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        emu_.Get<Imx51Gpu3dRaster>();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t a) override {
        switch ((a - kBase) >> 2) {
            case kIdxPmOverride1: return pm_override1_;
            case kIdxPmOverride2: return pm_override2_;
            case kIdxRbbmStatus:  return kRbbmStatusIdle;
            case kIdxMasterIntSignal: return 0u;
            case kIdxPeriphId1:    return 0u;
            case kIdxPeriphId2:    return 0u;
            case kIdxPatchRelease: return 0u;
            case kIdxRbCntl:       return rb_cntl_;
            case kIdxRbWptr:       return wptr_;  /* regread returns rb->wptr, gsl_yamato_imx.c:791 */
        }
        if (auto it = reg_file_.find((a - kBase) >> 2); it != reg_file_.end())
            return it->second;  /* a register the guest programmed via a TYPE0 write */
        if (((a - kBase) >> 2) == kIdxSqInstStoreManagment)
            return 0u;  /* read-before-write power-on default (reg_file_ serves it once a restore writes it) */
        HaltUnsupportedAccess("ReadWord", a, 0);
    }
    void WriteWord(uint32_t a, uint32_t v) override {
        const uint32_t idx = (a - kBase) >> 2;
        if ((idx >= kIdxScratchReg0 && idx <= kIdxScratchReg7) || idx == kIdxScratchAddr || idx == kIdxScratchUmsk) {
            WriteRegister(idx, v); return;
        }
        switch ((a - kBase) >> 2) {
            case kIdxPmOverride1: pm_override1_ = v; return;
            case kIdxPmOverride2: pm_override2_ = v; return;
            case kIdxSoftReset:       return;
            case kIdxRbbmCntl:        return;
            case kIdxRbbmIntCntl:     return;
            case kIdxCpIntCntl:       return;
            case kIdxRbWptrBase:      return;
            case kIdxRbWptrDelay:     return;
            case kIdxMhArbiterConfig: return;
            case kIdxSqVsProgram:
            case kIdxSqPsProgram: WriteRegister(idx, v); return;
            /* NXP linux-imx a1638da9, gsl_mmu.c:506-526; Mesa e97ad748 a2xx.xml:1042, BEH_NEVR. */
            case kIdxMhMmuConfig:
                reg_file_[kIdxMhMmuConfig] = v;
                if ((v & 1u) && v != 1u) HaltUnsupportedAccess("GPU MMU configuration", a, v);
                return;
            case kIdxMhInterruptMask: return;
            case kIdxMhMmuMpuBase:    return;
            case kIdxMhMmuMpuEnd:     return;
            case kIdxRbCntl:          rb_cntl_ = v; return;
            /* NXP a1638da9 gsl_yamato.c:36-58, kgsl_yamato_gmeminit. */
            case kIdxRbEdramInfo: reg_file_[idx] = v; return;
            case kIdxCpIntAck:
            case kIdxCpDebug:
            case kIdxMeCntl:
            case kIdxMeRamWaddr:
            case kIdxMeRamData:
            case kIdxPfpUcodeAddr:
            case kIdxPfpUcodeData:
            case kIdxQueueThresh:     return;
            /* RB_BASE (re)inits the ring: reset the read/write cursor to match
               kgsl_ringbuffer_start's rb->rptr=rb->wptr=0 (kgsl_ringbuffer.c:419). */
            case kIdxRbBase:          rb_base_ = v; rptr_ = 0; wptr_ = 0; return;
            case kIdxRbRptrAddr:      rb_rptr_addr_ = v; return;
            case kIdxRbWptr:          HandleRbWptr(v); return;
        }
        HaltUnsupportedAccess("WriteWord", a, v);
    }

    void SaveState(StateWriter& w) override {
        w.Write("pm_override1", pm_override1_);
        w.Write("pm_override2", pm_override2_);
        w.Write("rb_cntl", rb_cntl_);
        w.Write("rb_base", rb_base_);
        w.Write("rb_rptr_addr", rb_rptr_addr_);
        w.Write("rptr", rptr_);
        w.Write("wptr", wptr_);
        w.Write("reg_file_count", static_cast<uint32_t>(reg_file_.size()));
        for (const auto& [idx, val] : reg_file_) { w.Write("idx", idx); w.Write("val", val); }
        emu_.Get<Imx51Gpu3dContext>().SaveState(w);
        emu_.Get<Imx51Gpu3dDraw>().SaveState(w);
        emu_.Get<Imx51Gpu3dRaster>().SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("pm_override1", pm_override1_);
        r.Read("pm_override2", pm_override2_);
        r.Read("rb_cntl", rb_cntl_);
        r.Read("rb_base", rb_base_);
        r.Read("rb_rptr_addr", rb_rptr_addr_);
        r.Read("rptr", rptr_);
        r.Read("wptr", wptr_);
        uint32_t n = 0;
        r.Read("reg_file_count", n);
        reg_file_.clear();
        for (uint32_t k = 0; k < n; ++k) {
            uint32_t idx = 0, val = 0;
            r.Read("idx", idx);
            r.Read("val", val);
            reg_file_[idx] = val;
        }
        emu_.Get<Imx51Gpu3dContext>().RestoreState(r);
        emu_.Get<Imx51Gpu3dDraw>().RestoreState(r);
        emu_.Get<Imx51Gpu3dRaster>().RestoreState(r);
    }

private:
    uint32_t MmuConfig() const {
        const auto config = reg_file_.find(kIdxMhMmuConfig);
        return config == reg_file_.end() ? 0u : config->second;
    }
    uint8_t* ReadSpan(uint64_t pa, uint64_t size) {
        return emu_.Get<Imx51Gpu3dMemory>().ReadSpan(pa, size, MmuConfig());
    }
    uint8_t* WriteSpan(uint64_t pa, uint64_t size) {
        return emu_.Get<Imx51Gpu3dMemory>().WriteSpan(pa, size, MmuConfig());
    }
    uint32_t ReadPa32(uint64_t pa) {
        return emu_.Get<Imx51Gpu3dMemory>().ReadPa32(pa, MmuConfig());
    }
    void WritePa32(uint64_t pa, uint32_t value) {
        emu_.Get<Imx51Gpu3dMemory>().WritePa32(pa, value, MmuConfig());
    }

    Imx51Gpu3dPacket DecodePacket(uint64_t address, uint32_t available,
                                  Imx51Gpu3dPacketSource source) {
        if (address > UINT32_MAX || (address & 3u) != 0 || available == 0)
            HaltUnsupportedAccess("PM4 malformed header address/extent", static_cast<uint32_t>(address), available);
        const uint32_t header = ReadPa32(address);
        Imx51Gpu3dPacket packet;
        if (const char* error = Imx51Gpu3dPacket::Decode(header, address, available, source, packet))
            HaltUnsupportedAccess(error, static_cast<uint32_t>(address), header);
        return packet;
    }

    uint32_t ReadOperand(const Imx51Gpu3dPacket& packet, uint32_t index) {
        uint64_t address = 0;
        if (!packet.OperandAddress(index, address))
            HaltUnsupportedAccess("PM4 malformed operand index", static_cast<uint32_t>(packet.address), index);
        return ReadPa32(address);
    }

    /* NXP linux-imx a1638da9, yamato_offset.h:450-465; gsl_ringbuffer.c:1038-1054. */
    void WriteRegister(uint32_t idx, uint32_t value) {
        switch (idx) {
            /* NXP linux-imx a1638da9, gsl_yamato.c:353-354; yamato_registers.h: SQ_VS_PROGRAM/SQ_PS_PROGRAM. */
            case kIdxSqVsProgram: case kIdxSqPsProgram:
                if (value) HaltUnsupportedAccess("unsupported shader program selector", kBase + idx * 4u, value);
                break;
            /* NXP linux-imx a1638da9, yamato_registers.h: SCRATCH_ADDR; gsl_ringbuffer.h:196-201. */
            case kIdxScratchAddr:
                if (value & 31u) HaltUnsupportedAccess("SCRATCH_ADDR unsupported alignment", kBase + idx * 4u, value);
                break;
            case kIdxScratchUmsk:
                if (value > 1u) HaltUnsupportedAccess("SCRATCH_UMSK unsupported mask/swap", kBase + idx * 4u, value);
                break;
            case kIdxPmOverride1: case kIdxPmOverride2: WriteWord(kBase + idx * 4u, value); return;
            case kIdxSoftReset: case kIdxRbbmCntl: case kIdxRbbmIntCntl: case kIdxCpIntCntl:
            case kIdxRbWptrBase: case kIdxRbWptrDelay: case kIdxMhArbiterConfig:
            case kIdxMhMmuConfig: case kIdxMhInterruptMask: case kIdxMhMmuMpuBase: case kIdxMhMmuMpuEnd:
            case kIdxRbCntl: case kIdxRbBase: case kIdxRbRptrAddr: case kIdxRbWptr:
            case kIdxCpIntAck: case kIdxCpDebug:
            case kIdxMeCntl: case kIdxMeRamWaddr: case kIdxMeRamData: case kIdxPfpUcodeAddr:
            case kIdxPfpUcodeData: case kIdxQueueThresh: case kIdxRbbmStatus:
            case kIdxMasterIntSignal: case kIdxPeriphId1: case kIdxPeriphId2: case kIdxPatchRelease:
                HaltUnsupportedAccess("PM4 unsupported control register write", kBase + idx * 4u, value);
            default: break;
        }
        /* NXP linux-imx a1638da9, gsl_ringbuffer.c:527-531,833-838; gsl_cmdstream.h: GSL_CMDSTREAM_GET_SOP_TIMESTAMP. */
        if (idx == kIdxScratchReg0) {
            const auto mask = reg_file_.find(kIdxScratchUmsk);
            if (mask != reg_file_.end() && mask->second != 0u) {
                const auto address = reg_file_.find(kIdxScratchAddr);
                if (mask->second != 1u || address == reg_file_.end() || (address->second & 31u) != 0)
                    HaltUnsupportedAccess("scratch timestamp unsupported configuration", kBase + idx * 4u, value);
                WritePa32(address->second, value);
            }
        }
        emu_.Get<Imx51Gpu3dContext>().ShadowWrite(idx, value, MmuConfig());
        reg_file_[idx] = value;
    }

    /* NXP linux-imx gsl_pm4types.h: pm4_type0 and pm4_type0_packet_for_sameregister. */
    void StoreType0(const Imx51Gpu3dPacket& packet) {
        const uint32_t hdr = packet.header, cnt = packet.payload_count;
        const uint32_t regindx = hdr & 0x7FFFu;
        const bool     same    = packet.same_register;
        for (uint32_t k = 0; k < cnt; ++k)
            WriteRegister(same ? regindx : regindx + k, ReadOperand(packet, k));
    }

    /* NXP linux-imx gsl_drawctxt.c: reg_to_mem, build_reg_to_mem_range and PM4_REG. */
    void StoreSetConstant(const Imx51Gpu3dPacket& packet) {
        const uint32_t pa = static_cast<uint32_t>(packet.address), cnt = packet.payload_count;
        const uint32_t tgt    = ReadOperand(packet, 0u);
        const uint32_t offset = tgt & 0xFFFFu;
        uint32_t base = 0u;
        switch ((tgt >> 16) & 0x7u) {
            case 0u: base = kScBaseAlu;   break;
            case 1u: base = kScBaseFetch; break;
            case 2u: base = kScBaseBool;  break;
            case 3u: base = kScBaseLoop;  break;
            case 4u: base = kScBaseReg;   break;
            default: HaltUnsupportedAccess("SET_CONSTANT type", static_cast<uint32_t>(pa), tgt);
        }
        for (uint32_t j = 0; j + 1u < cnt; ++j)
            WriteRegister(base + offset + j, ReadOperand(packet, j + 1u));
    }

    /* NXP linux-imx gsl_pm4types.h: PM4_HDR_INDIRECT_BUFFER. */
    void ScanIb(uint32_t ibaddr, uint32_t sizedwords, uint32_t depth = 1u) {
        /* NXP linux-imx yamato/22/yamato_registers.h: CP_IB1/2_BASE, CP_IB1/2_BUFSZ. */
        if ((ibaddr & 3u) != 0 || sizedwords == 0 || sizedwords > 0xFFFFFu)
            HaltUnsupportedAccess("CP IB address/size", ibaddr, sizedwords);
        ReadSpan(ibaddr, uint64_t(sizedwords) * 4u);
        for (uint32_t i = 0; i < sizedwords; ) {
            const auto packet = DecodePacket(uint64_t(ibaddr) + uint64_t(i) * 4u,
                                             sizedwords - i, Imx51Gpu3dPacketSource::IndirectBuffer);
            const uint32_t pa = static_cast<uint32_t>(packet.address), hdr = packet.header;
            const uint32_t cnt = packet.payload_count;
            if (packet.type == kPm4Type0) { StoreType0(packet); i += 1u + cnt; continue; }
            if (packet.type == kPm4Type2) { i += 1u; continue; }
            switch (packet.opcode) {
                /* NXP linux-imx gsl_debug_pm4.c: WritePM4Packet_Type3, IB1/IB2 traversal. */
                case kPm4OpIndirectBuffer:
                case kPm4OpIndirectBufferPfd:
                    if (depth >= 2u)
                        HaltUnsupportedAccess("CP unsupported IB nesting depth", pa, depth);
                    if (cnt != 2u)
                        HaltUnsupportedAccess("CP IB packet length", pa, cnt);
                    ScanIb(ReadOperand(packet, 0u), ReadOperand(packet, 1u), depth + 1u);
                    break;
                case kPm4OpNop:
                case kPm4OpWaitForIdle:
                case kPm4OpInvalidateState: break;  /* invalidates GPU pipeline state groups so later draws reload; CERF's GPU3D caches no cross-draw state (each C2D blit reads its config fresh from reg_file_), so nothing to flush -> inert */
                case kPm4OpLoadConstantContext: emu_.Get<Imx51Gpu3dContext>().Load(packet, reg_file_, MmuConfig()); break;
                case kPm4OpImStore: case kPm4OpImLoad: case kPm4OpImLoadImmediate:
                case kPm4OpSetShaderBases: case 0x4Bu: case 0x34u:
                    emu_.Get<Imx51Gpu3dDraw>().Packet(packet, reg_file_, MmuConfig()); break;
                case kPm4OpRegRmw: HandleRegRmw(packet); break;
                case kPm4OpWaitRegEq: {  /* [reg][ref][mask][poll] (lib2d-z430 emitter sub_41A62890); the Z430 completes synchronously, so the wait is met by the current register state, else self-reveal */
                    const uint32_t reg  = ReadOperand(packet, 0u);
                    const uint32_t ref  = ReadOperand(packet, 1u);
                    const uint32_t mask = ReadOperand(packet, 2u);
                    if ((ReadWord(kBase + reg * 4u) & mask) != ref)
                        HaltUnsupportedAccess("WAIT_REG_EQ condition unmet", static_cast<uint32_t>(pa), reg);
                    break;
                }
                case kPm4OpSetConstant: StoreSetConstant(packet); break;
                case kPm4OpMemWrite: HandleMemWrite(packet); break;
                case kPm4OpRegToMem: HandleRegToMem(packet); break;
                case kPm4OpEventWrite: HandleEventWrite(packet); break;  /* blit-tail CACHE_FLUSH (cnt=1) / CACHE_FLUSH_TS */
                case kPm4OpDrawIndx: HandleDrawIndx(packet); break;
                default:
                    HaltUnsupportedAccess("IB opcode", static_cast<uint32_t>(pa), hdr);  /* unknown draw/opcode */
            }
            i += 1u + cnt;
        }
    }

    /* NXP linux-imx a1638da9, gsl_drawctxt.c:1233-1245, shader partition fixup. */
    void HandleRegRmw(const Imx51Gpu3dPacket& packet) {
        if (packet.payload_count != 3u)
            HaltUnsupportedAccess("REG_RMW payload length", static_cast<uint32_t>(packet.address), packet.payload_count);
        const uint32_t target = ReadOperand(packet, 0u);
        if (target != kIdxScratchReg2)
            HaltUnsupportedAccess("REG_RMW unsupported target/flags", static_cast<uint32_t>(packet.address), target);
        const uint32_t and_mask = ReadOperand(packet, 1u), or_mask = ReadOperand(packet, 2u);
        WriteRegister(target, (ReadWord(kBase + target * 4u) & and_mask) | or_mask);
    }

    /* NXP linux-imx a1638da9, gsl_pm4types.h: PM4_MEM_WRITE;
       Mesa e97ad748, adreno_pm4.xml: CP_MEM_WRITE A2XX-A4XX;
       sync_2 EA5T-14D544-BA.sec, librenderboy.dll: 0x41CCCE5C. */
    void HandleMemWrite(const Imx51Gpu3dPacket& packet) {
        const uint32_t pa = static_cast<uint32_t>(packet.address);
        if (packet.payload_count < 2u)
            HaltUnsupportedAccess("PM4 malformed MEM_WRITE payload", pa, packet.header);
        const uint32_t destination = ReadOperand(packet, 0u);
        if ((destination & 3u) != 0)
            HaltUnsupportedAccess("MEM_WRITE unsupported address low bits", pa, destination);
        const uint32_t packet_bytes = (packet.payload_count + 1u) * 4u;
        const uint32_t data_bytes = (packet.payload_count - 1u) * 4u;
        const uint8_t* source = ReadSpan(packet.address, packet_bytes);
        uint8_t* target = WriteSpan(destination, data_bytes);
        const uint64_t source_host = reinterpret_cast<uintptr_t>(source);
        const uint64_t target_host = reinterpret_cast<uintptr_t>(target);
        if (target_host < source_host + packet_bytes && source_host < target_host + data_bytes)
            HaltUnsupportedAccess("MEM_WRITE unsupported packet overlap", pa, destination);
        std::memcpy(target, source + 8u, data_bytes);
    }

    /* EVENT_WRITE/CACHE_FLUSH_TS: write the EOP timestamp the guest polls via
       kgsl_cmdstream_check_timestamp (kgsl_ringbuffer.c:635-640); addr+value inline. */
    void HandleEventWrite(const Imx51Gpu3dPacket& packet) {
        const uint32_t pa = static_cast<uint32_t>(packet.address);
        const uint32_t event = ReadOperand(packet, 0u);
        if (event == kEventCacheFlush) return;  /* no writeback; GPU MMU off -> DRAM already coherent */
        if (event != kEventCacheFlushTs)
            HaltUnsupportedAccess("CP EVENT_WRITE event", pa, event);
        const uint32_t addr = ReadOperand(packet, 1u);
        WritePa32(addr, ReadOperand(packet, 2u));
    }

    /* REG_TO_MEM (draw-context save, kgsl_drawctxt.c reg_to_mem:416 /
       build_reg_to_mem_range:438): read GPU register `src` and write its value to
       memory at `dst`. Packet: [hdr cnt=2][src reg index (| shadow flag)][dst gpuaddr]. */
    void HandleRegToMem(const Imx51Gpu3dPacket& packet) {
        const uint32_t src   = ReadOperand(packet, 0u) & ~kRegToMemShadowFlag;
        const uint32_t dst   = ReadOperand(packet, 1u);
        const uint32_t value = ReadWord(kBase + src * 4u);  /* register-file / modeled read; unmodeled -> FATAL, self-revealing */
        WritePa32(dst, value);
    }

    void HandleDrawIndx(const Imx51Gpu3dPacket& packet) {
        const uint32_t control = ReadOperand(packet, 1u);
        if (control == 0x00040086u)
            emu_.Get<Imx51Gpu3dBlit>().Draw(control, packet.address, reg_file_, MmuConfig());
        else emu_.Get<Imx51Gpu3dDraw>().Packet(packet, reg_file_, MmuConfig());
    }

    /* NXP linux-imx gsl_ringbuffer.c: gsl_ringbuffer_sizelog2quadwords;
       yamato/22/yamato_registers.h: CP_RB_BASE, CP_RB_CNTL and CP_RB_WPTR. */
    void HandleRbWptr(uint32_t wptr) {
        const uint32_t shift = rb_cntl_ & 0x3Fu;
        if (shift >= 20u || (rb_base_ & 31u) != 0 || (rb_cntl_ & 0x30000u) != 0)
            HaltUnsupportedAccess("CP ring geometry/swap", rb_base_, rb_cntl_);
        const uint32_t size = 2u << shift;
        if (wptr >= size || rptr_ >= size)
            HaltUnsupportedAccess("CP ring cursor", rb_base_, wptr);
        ReadSpan(rb_base_, uint64_t(size) * 4u);
        if ((rb_cntl_ & 0x08000000u) == 0 && (rb_rptr_addr_ & 3u) != 0)
            HaltUnsupportedAccess("CP RPTR unsupported swap", rb_rptr_addr_, rb_cntl_);
        wptr_ = wptr;
        ScanRing(size);
    }

    /* NXP linux-imx gsl_ringbuffer.c: kgsl_ringbuffer_waitspace, kgsl_ringbuffer_addcmds. */
    void ScanRing(uint32_t size) {
        while (rptr_ != wptr_) {
            const uint32_t available = (wptr_ + size - rptr_) % size;
            const uint32_t tail = size - rptr_;
            const auto packet = DecodePacket(uint64_t(rb_base_) + uint64_t(rptr_) * 4u,
                                             available < tail ? available : tail,
                                             Imx51Gpu3dPacketSource::Ring);
            const uint32_t pa = static_cast<uint32_t>(packet.address), hdr = packet.header;
            const uint32_t count = 1u + packet.payload_count;
            if (count > tail)
                HaltUnsupportedAccess("CP ring packet crosses tail", pa, hdr);
            if (count > available) {
                if (packet.type == kPm4Type3 && packet.opcode == kPm4OpNop && count == tail)
                    return;
                HaltUnsupportedAccess("CP ring truncated packet", pa, hdr);
            }
            if (packet.type == kPm4Type0) StoreType0(packet);
            if (packet.type == kPm4Type3) {
                switch (packet.opcode) {
                    case kPm4OpMeInit:
                    case kPm4OpNop:
                    case kPm4OpWaitForIdle: break;
                    case kPm4OpIndirectBuffer:
                    case kPm4OpIndirectBufferPfd:
                        if (packet.payload_count != 2u)
                            HaltUnsupportedAccess("CP IB packet length", pa, packet.payload_count);
                        ScanIb(ReadOperand(packet, 0u), ReadOperand(packet, 1u));
                        break;
                    case kPm4OpEventWrite: HandleEventWrite(packet); break;
                    case kPm4OpMemWrite: HandleMemWrite(packet); break;
                    case kPm4OpLoadConstantContext: emu_.Get<Imx51Gpu3dContext>().Load(packet, reg_file_, MmuConfig()); break;
                    case kPm4OpRegRmw: HandleRegRmw(packet); break;
                    case kPm4OpDrawIndx: HandleDrawIndx(packet); break;
                    case kPm4OpImStore: case kPm4OpImLoad: case kPm4OpImLoadImmediate:
                    case kPm4OpSetShaderBases: case 0x4Bu: case 0x34u:
                        emu_.Get<Imx51Gpu3dDraw>().Packet(packet, reg_file_, MmuConfig()); break;
                    /* MCIMX51RM Table 3-2: GPU3D IRQ102 idle indication. */
                    case kPm4OpInterrupt: break;
                    default: HaltUnsupportedAccess("CP ring-scan opcode", pa, hdr);
                }
            }
            rptr_ = (rptr_ + count) % size;
            /* NXP linux-imx gsl_ringbuffer.c: kgsl_ringbuffer_start, rb_no_update. */
            if ((rb_cntl_ & 0x08000000u) == 0)
                WritePa32(rb_rptr_addr_, rptr_);
        }
    }

    uint32_t pm_override1_ = 0;
    uint32_t pm_override2_ = 0;
    uint32_t rb_cntl_      = 0;
    uint32_t rb_base_      = 0;
    uint32_t rb_rptr_addr_ = 0;
    uint32_t rptr_         = 0;
    uint32_t wptr_         = 0;
    std::unordered_map<uint32_t, uint32_t> reg_file_;  /* GPU3D registers/constants the guest programs (TYPE0 / SET_CONSTANT), served on a REG_TO_MEM save */
};

}  /* namespace */

REGISTER_SERVICE(Imx51Gpu3d);
