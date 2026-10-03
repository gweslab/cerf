#pragma once

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/raster_scan_clock.h"

#include <cstdint>

class StateWriter;
class StateReader;

class OdoArm720AudioPlayer : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    void SetPlaybackEnabled(bool enabled);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    void ResetLine();
    void CheckDacRate();
    void RequireScan(bool placed, const char* what);
    void ArmPageEnd(uint64_t now);
    void OnPageEnd();
    void QueuePage(uint32_t page, uint32_t first_sample);
    void OnRateChange();

    GuestCycleClock*        clock_   = nullptr;
    GuestCycleClock::Event* event_   = nullptr;
    RasterScanClock         scan_;
    PacedWaveOut            out_;
    bool                    playing_ = false;
};
