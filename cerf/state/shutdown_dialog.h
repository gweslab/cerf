#pragma once

#include "../host/modal_dialog.h"

enum class ShutdownChoice { Cancel, Exit, ExitSave, SoftReset, HardReset };

enum class ShutdownTrigger { WindowClose, DeepSleep };

class ShutdownDialog : public ModalDialog {
public:
    using ModalDialog::ModalDialog;

    ShutdownChoice Show(ShutdownTrigger trigger = ShutdownTrigger::WindowClose);

    void DismissAsCancel();

private:
    bool DpiScaledLayout() const override { return true; }
    void BuildControls(HWND hwnd) override;
    void OnShown() override;
    void OnPaint(HDC dc) override;
    void OnCommand(int id, int notify) override;
    bool OnMessage(UINT msg, WPARAM wp, LPARAM lp) override;

    int  SelectedAction() const;
    void SyncActionBlock();
    void LayoutSaveRow();
    void CommitOk();
    void StopTimer();
    int  BarFillWidth() const;
    int  RemainingSeconds() const;
    RECT BarRect() const;
    RECT CountdownRect() const;

    HWND combo_        = nullptr;
    HWND chk_save_     = nullptr;
    HWND save_link_    = nullptr;
    HWND save_tail_    = nullptr;
    HWND chk_remember_ = nullptr;
    HWND desc_         = nullptr;

    ShutdownTrigger trigger_ = ShutdownTrigger::WindowClose;
    ShutdownChoice  choice_  = ShutdownChoice::Cancel;

    int  band_h_    = 0;
    bool timer_on_  = false;
    unsigned long long deadline_tick_ = 0;
    int  remaining_ms_   = 0;
    int  painted_fill_w_ = -1;
    int  painted_secs_   = -1;
};
