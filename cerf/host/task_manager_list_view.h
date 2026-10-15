#pragma once

#include "../peripherals/cerf_virt/cerf_virt_task_manager.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <vector>

class UiLanguage;

/* The report-mode ListView inside the guest task-manager window. Renders one of
   two modes - top-level windows or processes - from a CerfVirtTaskManager
   snapshot while preserving the selected row (by lParam) across refreshes.
   UI-thread only; a plain helper owned by TaskManagerWindow, not a Service. */
class TaskManagerListView {
public:
    enum class Mode { Windows, Processes };

    HWND Create(HWND parent, int ctrl_id, HFONT font, UiLanguage& language);
    HWND Hwnd() const { return list_; }
    void ApplyDarkColors(COLORREF bg, COLORREF text);
    void Move(int x, int y, int w, int h);
    void SelectRow(int item);

    Mode GetMode() const { return mode_; }
    void SetMode(Mode m);   /* rebuilds columns + clears rows for a fresh fill */

    int DisplayedCount() const { return displayed_; }   /* rows actually shown */

    /* Rebuilds rows when the snapshot changed for the active mode; returns true
       when the visible list was rebuilt (caller refreshes the window title). */
    bool Update(const CerfVirtTaskManager::Snapshot& snap);

    bool SelectedProc(uint32_t* pid) const;
    bool SelectedWindow(uint32_t* hwnd, uint32_t* pid) const;

private:
    UiLanguage* language_ = nullptr;
    static LRESULT CALLBACK ListProcStatic(HWND, UINT, WPARAM, LPARAM);
    void SetColumns();
    void Fill();
    bool SelectedLParam(uint32_t* out) const;

    HWND     list_      = nullptr;
    Mode     mode_      = Mode::Windows;
    uint64_t shown_gen_ = 0;
    int      displayed_ = 0;
    WNDPROC  list_base_proc_ = nullptr;   /* dark-mode header-text subclass */
    COLORREF header_text_    = RGB(0, 0, 0);
    std::vector<CerfVirtTaskManager::ProcEntry> procs_;
    std::vector<CerfVirtTaskManager::WinEntry>  wins_;
};
