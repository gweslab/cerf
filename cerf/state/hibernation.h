#pragma once

#include "../core/service.h"
#include "state_image_format.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <thread>

class StateWriter;
class StateReader;

/* Callers must run Save/Restore on a thread other than the JIT thread -
   JitRunner::Pause self-deadlocks if called from the JIT thread. */
class Hibernation : public Service {
public:
    using Service::Service;
    ~Hibernation() override;

    void OnReady() override;

    /* state.img in the device directory - the implicit save/restore target. */
    std::wstring DefaultStatePath() const;
    bool         DefaultStateExists() const;

    /* Signaled when the most recent SaveAsync/RestoreAsync worker finishes. */
    HANDLE DoneEvent() const { return done_event_; }

    bool Save(const std::wstring& path);
    bool Restore(const std::wstring& path, bool ram_only = false,
                 bool cold_boot_on_failure = false);

    /* Runs the op on a worker. on_done (if set) fires on that worker thread
       at completion - UI work inside it must marshal to the UI thread.
       Serialized: a new call joins the previous worker first. */
    void SaveAsync(const std::wstring& path, std::function<void()> on_done = {});
    void RestoreAsync(const std::wstring& path, bool ram_only = false);

    void OnShutdown() override;

private:
    std::wstring     DeviceDirFile(const wchar_t* name) const;
    StateImageHeader LiveHeader() const;
    bool             WriteImage(const std::wstring& path);
    void             SaveSection(StateWriter& w, StateSection section);
    void             RestoreSection(StateReader& r, StateSection section);
    void             ReadHeader(StateReader& r);
    void             ApplyImage(StateReader& r, bool ram_only);
    void             RollBack(const std::wstring& rollback_path);
    void             RestorePeripherals(StateReader& r);
    void             RestorePresentation(StateReader& r);
    uint32_t         PeripheralLayoutSig() const;
    void     Progress(const char* fmt, ...);
    void     AwaitFailureAck(bool cold_boot);
    void     JoinWorker();

    std::thread worker_;
    HANDLE      done_event_ = nullptr;
};
