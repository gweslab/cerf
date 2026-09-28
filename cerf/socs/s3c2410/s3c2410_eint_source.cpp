#include "s3c2410_eint_source.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"

REGISTER_SERVICE(S3C2410EintSource);

bool S3C2410EintSource::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
}

void S3C2410EintSource::SetSink(S3C2410EintSink* sink) {
    if (sink_ && sink_ != sink) {
        LOG(Caution, "S3C2410EintSource::SetSink: a second sink registered\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    sink_ = sink;
}

void S3C2410EintSource::DriveEintPin(int eint, bool level) {
    if (!sink_) {
        LOG(Caution, "S3C2410EintSource::DriveEintPin: EINT%d with no sink\n", eint);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    sink_->DriveEintPin(eint, level);
}

void S3C2410EintSource::ReassertHeldLevelEints(uint32_t cleared_srcpnd) {
    if (!sink_) {
        emu_.Get<Fatal>().Die(
            "S3C2410EintSource: no EINT sink for cleared SRCPND 0x%08X",
            cleared_srcpnd);
    }
    sink_->ReassertHeldLevelEints(cleared_srcpnd);
}

void S3C2410EintSource::RegisterUnmaskListener(std::function<void(uint32_t)> fn) {
    unmask_listeners_.push_back(std::move(fn));
}

void S3C2410EintSource::NotifyUnmasked(uint32_t unmasked_intmsk) {
    for (auto& fn : unmask_listeners_) fn(unmasked_intmsk);
}
