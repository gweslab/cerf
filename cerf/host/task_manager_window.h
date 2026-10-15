#pragma once

#include "../core/service.h"
#include "task_manager_list_view.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>

/* Non-modal guest task-manager window (guest additions): a tabbed live view of
   top-level windows ("Windows", default) or processes ("Processes"), with
   switch-to / kill / run controls, backed by CerfVirtTaskManager. UI-thread
   only. */
class TaskManagerWindow : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    /* UI thread (widget menu action). Creates the window or raises it. */
    void Show();

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK RunEditProcStatic(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK TabProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);
    void    DrawTab(const DRAWITEMSTRUCT* di);

    void BuildControls();
    void LayoutControls();
    void OnTick();
    void OnTabChanged();
    void RequestActiveList();
    void DoSwitchTo();
    void DoKill();
    void DoRun();
    void ShowRowMenu(int item, POINT screen_pt);
    void SetStatus(const std::wstring& text, COLORREF clr);
    void UpdateTitle(const CerfVirtTaskManager::Snapshot& snap);
    const wchar_t* ActionName(uint32_t code) const;

    HWND                hwnd_       = nullptr;
    HWND                tabs_       = nullptr;
    TaskManagerListView list_;
    HWND                run_label_  = nullptr;
    HWND                run_edit_   = nullptr;
    HWND                btn_run_    = nullptr;
    HWND                btn_switch_ = nullptr;
    HWND                btn_kill_   = nullptr;
    HWND                status_     = nullptr;
    WNDPROC             run_edit_base_proc_ = nullptr;
    WNDPROC             tabs_base_proc_     = nullptr;

    uint32_t run_ticket_     = 0;
    bool     awaiting_first_ = true;
    COLORREF status_clr_     = RGB(0, 0, 0);
};
