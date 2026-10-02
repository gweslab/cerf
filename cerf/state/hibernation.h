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
    bool Restore(const std::wstring& path, bool ram_only = false);

    void SaveAsync(const std::wstring& path, std::function<void(bool)> on_done = {});
    void RestoreAsync(const std::wstring& path, bool ram_only = false);

    void OnShutdown() override;

private:
    std::wstring     DeviceDirFile(const wchar_t* name) const;
    StateImageHeader LiveHeader() const;
    bool             WriteImage(const std::wstring& path, std::string& error);
    void             SaveSection(StateWriter& w, StateSection section);
    void             RestoreSection(StateReader& r, StateSection section);
    void             ReadHeader(StateReader& r);
    void             ApplyImage(StateReader& r, bool ram_only);
    bool             ApplyStateFile(StateReader& r, bool ram_only, std::string& reason);
    void             RollBack(const std::wstring& rollback_path);
    void             RestorePeripherals(StateReader& r);
    void             RestorePresentation(StateReader& r);
    uint32_t         PeripheralLayoutSig() const;
    void     Progress(const char* fmt, ...);
    void     JoinWorker();

    std::thread worker_;
    HANDLE      done_event_ = nullptr;
};
