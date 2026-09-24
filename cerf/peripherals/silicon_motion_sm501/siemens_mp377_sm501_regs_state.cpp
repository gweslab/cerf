#include "siemens_mp377_sm501_blitter.h"
#include "siemens_mp377_sm501_internal.h"
#include "siemens_mp377_sm501_regs.h"

#include "../../core/cerf_emulator.h"

namespace siemens_mp377 {

void SiemensMp377Sm501Regs::SaveState(StateWriter& w) {
    auto audio_pacer_lock = emu_.Get<SiemensMp377Sm501AudioOutput>().LockForState();

    w.WriteBytes("regs", regs_.data(), regs_.size() * sizeof(regs_[0]));
    w.Write("panel_fb_raw", panel_fb_raw_);
    w.Write("panel_pitch_bytes", panel_pitch_bytes_);

    emu_.Get<SiemensMp377Sm501Blitter>().SaveState(w);
    emu_.Get<SiemensMp377Sm501Video>().SaveState(w);

    emu_.Get<SiemensMp377Sm501Ac97>().SaveState(w);
    emu_.Get<SiemensMp377Sm501AudioMcu>().SaveState(w);
    emu_.Get<SiemensMp377Sm501AudioOutput>().SaveState(w);

    emu_.Get<SiemensMp377TouchPanel>().SaveState(w);
}

void SiemensMp377Sm501Regs::RestoreState(StateReader& r) {
    emu_.Get<SiemensMp377Sm501AudioOutput>().SetPacerEnabled(false);

    r.ReadBytes("regs", regs_.data(), regs_.size() * sizeof(regs_[0]));
    r.Read("panel_fb_raw", panel_fb_raw_);
    r.Read("panel_pitch_bytes", panel_pitch_bytes_);

    emu_.Get<SiemensMp377Sm501Blitter>().RestoreState(r);
    emu_.Get<SiemensMp377Sm501Video>().RestoreState(r);

    emu_.Get<SiemensMp377Sm501Ac97>().RestoreState(r);
    emu_.Get<SiemensMp377Sm501AudioMcu>().RestoreState(r);
    emu_.Get<SiemensMp377Sm501AudioOutput>().RestoreState(r);

    emu_.Get<SiemensMp377TouchPanel>().RestoreState(r);
}

void SiemensMp377Sm501Regs::PostRestore() {
    RefreshSm501InterruptLine();
    emu_.Get<SiemensMp377TouchPanel>().PostRestore();
}

} // namespace siemens_mp377
