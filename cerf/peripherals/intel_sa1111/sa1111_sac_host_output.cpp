#include "sa1111_sac_host_output.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "sa1111_system_controller.h"

namespace {

constexpr uint16_t kChannels      = 2u;
constexpr uint16_t kBitsPerSample = 16u;

uint32_t RoundedHz(uint64_t num, uint64_t den) {
    return static_cast<uint32_t>((num + den / 2u) / den);
}

}

bool Sa1111SacHostOutput::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SacHostOutput::OnReady() {
    uint64_t num = 0, den = 1;
    emu_.Get<Sa1111SystemController>().AudioFrameRate(num, den);
    rate_ = RoundedHz(num, den);
    out_.Start("Sa1111Sac", rate_, kChannels, kBitsPerSample, true);
}

void Sa1111SacHostOutput::OnShutdown() { out_.Stop(); }

void Sa1111SacHostOutput::SetRate(uint64_t fs_num, uint64_t fs_den) {
    const uint32_t rate = RoundedHz(fs_num, fs_den);
    if (rate == rate_) return;
    rate_ = rate;
    out_.SetFormat(rate, kChannels, kBitsPerSample);
}

void Sa1111SacHostOutput::Begin() {
    if (active_) return;
    out_.BeginAudioOut({});
    active_ = true;
}

void Sa1111SacHostOutput::End() {
    if (active_) out_.FinishAudioOut();
    active_ = false;
}

void Sa1111SacHostOutput::Queue(const uint8_t* data, uint32_t bytes) {
    out_.QueueOutput(data, bytes);
}

void Sa1111SacHostOutput::Drop() {
    out_.StopAudioOut();
    active_ = false;
    rate_   = 0u;
}

REGISTER_SERVICE(Sa1111SacHostOutput);
