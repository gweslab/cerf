#include "trace_manager.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"

REGISTER_SERVICE(TraceManager);

#if CERF_DEV_MODE

#include "../boot/rom_parser_service.h"
#include "../jit/arm_mmu.h"

namespace {

/* CRC-32 / zlib (polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR
   0xFFFFFFFF). Compatible with `python -c "import zlib;
   print(hex(zlib.crc32(open('x','rb').read())))"` so callers can
   pre-compute the bundle CRC offline and embed it in trace files. */
uint32_t Crc32Update(uint32_t crc, const uint8_t* data, size_t n) {
    crc = ~crc;
    for (size_t i = 0; i < n; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return ~crc;
}

}  /* namespace */

std::optional<uint8_t> TraceContext::ReadVa8(uint32_t va) const {
    auto host = emu.Get<ArmMmu>().PeekDataTlb(va);
    if (!host) return std::nullopt;
    return **host;
}

std::optional<uint16_t> TraceContext::ReadVa16(uint32_t va) const {
    auto host = emu.Get<ArmMmu>().PeekDataTlb(va);
    if (!host) return std::nullopt;
    return *reinterpret_cast<const uint16_t*>(*host);
}

std::optional<uint32_t> TraceContext::ReadVa32(uint32_t va) const {
    auto host = emu.Get<ArmMmu>().PeekDataTlb(va);
    if (!host) return std::nullopt;
    return *reinterpret_cast<const uint32_t*>(*host);
}

void TraceManager::OnReady() {
    bundle_crc32_ = ComputeBundleCrc32();
    LOG(Trace, "bundle CRC32 = 0x%08X (awaiting trace registrations)\n",
        bundle_crc32_);
}

uint32_t TraceManager::ComputeBundleCrc32() const {
    uint32_t crc = 0;
    for (const auto& rom : emu_.Get<RomParserService>().Loaded()) {
        crc = Crc32Update(crc, rom.raw.data(), rom.raw.size());
    }
    return crc;
}

void TraceManager::RegisterForBundle(
        uint32_t expected_crc32,
        const std::function<void()>& register_fn) {
    if (expected_crc32 != bundle_crc32_) {
        ++bundles_skipped_;
        LOG(Trace, "skipping trace file (expected CRC 0x%08X, bundle is 0x%08X)\n",
            expected_crc32, bundle_crc32_);
        return;
    }
    ++bundles_matched_;
    register_fn();
}

void TraceManager::OnPc(uint32_t runtime_va, TraceHandler handler) {
    auto& vec = pc_traces_[runtime_va];
    for (const auto& e : vec) {
        if (!e.predicate.has_value()) {
            LOG(Caution, "TraceManager::OnPc duplicate registration at "
                         "runtime_va=0x%08X — another UNFILTERED trace handler "
                         "is already bound at this guest PC. Use OnPcFiltered "
                         "if you intended per-process filtering.\n", runtime_va);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
    vec.push_back({std::nullopt, std::move(handler)});
}

void TraceManager::OnPcFiltered(uint32_t       runtime_va,
                                TracePredicate predicate,
                                TraceHandler   handler) {
    pc_traces_[runtime_va].push_back(
        {std::optional<TracePredicate>{std::move(predicate)},
         std::move(handler)});
}

void TraceManager::OnRunLoopIter(TraceHandler handler) {
    iter_handlers_.push_back(std::move(handler));
}

bool TraceManager::HasPcTrace(uint32_t pc) const {
    if (pc_traces_.empty()) return false;
    return pc_traces_.count(pc) > 0;
}

void TraceManager::DispatchPc(uint32_t pc,
                              const uint32_t* regs, uint32_t cpsr) {
    auto it = pc_traces_.find(pc);
    if (it == pc_traces_.end()) return;
    TraceContext ctx{regs, cpsr, pc, emu_};
    for (const auto& e : it->second) {
        if (e.predicate.has_value() && !(*e.predicate)(ctx)) continue;
        e.handler(ctx);
    }
}

void TraceManager::DispatchRunLoopIter(const uint32_t* regs, uint32_t cpsr) {
    if (iter_handlers_.empty()) return;
    TraceContext ctx{regs, cpsr, regs[15], emu_};
    for (auto& h : iter_handlers_) h(ctx);
}

#else  /* production build */

void TraceManager::OnReady() {
    LOG(Trace, "cerf built for production; tracing disabled\n");
    return;
}

#endif  /* CERF_DEV_MODE */
