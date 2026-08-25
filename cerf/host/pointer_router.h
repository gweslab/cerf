#pragma once

#include "../core/service.h"

#include <mutex>
#include <string>
#include <vector>

class PointerSource;

class PointerRouter : public Service {
public:
    using Service::Service;

    void OnReady() override;

    void Register(PointerSource* src);

    std::vector<PointerSource*> Sources();
    PointerSource*              Active();
    void                        SetActive(PointerSource* src);
    void                        RestoreActiveByName(const std::wstring& name);
    void                        CycleNext();

    void ReevaluateAuto();
    void RearmAutoSelect();

    bool UserPicked() const;
    void RestoreUserPicked(bool picked);

private:
    void SelectAutoLocked();
    void NoteActiveLocked(PointerSource* before);

    mutable std::mutex          mtx_;
    std::vector<PointerSource*> sources_;
    PointerSource*              active_ = nullptr;
    bool                        user_picked_ = false;
};
