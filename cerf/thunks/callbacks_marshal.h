#pragma once
#include <windows.h>
#include <commctrl.h>
#include <cstdint>
#include <functional>
#include "../cpu/mem.h"

/* Callback executor type — matches Win32Thunks::CallbackExecutor */
using MarshalCallbackExecutor = std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)>;

/* Marshal WM_NOTIFY from native Win32 controls into ARM emulated memory.
   Returns true if the message was fully handled (result is set).
   Returns false if the caller should forward the message normally (ARM pointer case). */
bool MarshalNotify(HWND hwnd, WPARAM wParam, LPARAM lParam,
                   uint32_t arm_wndproc, EmulatedMemory& emem,
                   MarshalCallbackExecutor executor, LRESULT& out_result);

/* Marshal WM_WINDOWPOSCHANGING / WM_WINDOWPOSCHANGED.
   Always fully handles the message (returns result via out_result). */
void MarshalWindowPos(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                      uint32_t arm_wndproc, EmulatedMemory& emem,
                      MarshalCallbackExecutor executor, LRESULT& out_result);

/* Marshal WM_STYLECHANGING / WM_STYLECHANGED.
   Always fully handles the message. */
void MarshalStyleChange(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                        uint32_t arm_wndproc, EmulatedMemory& emem,
                        MarshalCallbackExecutor executor, LRESULT& out_result);

/* Marshal WM_SETTEXT: copy native string into ARM memory.
   Sets lParam to the ARM address. Caller continues with normal ARM callback. */
void MarshalSetText(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam);

/* Marshal WM_GETTEXT: provide ARM buffer, call ARM WndProc, copy result back.
   Always fully handles the message. */
void MarshalGetText(HWND hwnd, WPARAM wParam, LPARAM lParam,
                    uint32_t arm_wndproc, EmulatedMemory& emem,
                    MarshalCallbackExecutor executor, LRESULT& out_result);

/* Marshal WM_CREATE / WM_NCCREATE: convert CREATESTRUCTW to 32-bit ARM layout.
   Sets lParam to the ARM address. Caller continues with normal ARM callback. */
void MarshalCreateStruct(LPARAM lParam, EmulatedMemory& emem,
                         uint32_t emu_hinstance, LPARAM& out_lParam);

/* Marshal WM_DRAWITEM: convert DRAWITEMSTRUCT to 32-bit ARM layout.
   Sets lParam to the ARM address. Caller continues with normal ARM callback. */
void MarshalDrawItem(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam);

/* Marshal WM_MEASUREITEM: convert MEASUREITEMSTRUCT to 32-bit ARM layout.
   Sets lParam to the ARM address. Caller continues with normal ARM callback.
   After the ARM callback, call MarshalMeasureItemWriteback to copy results back. */
void MarshalMeasureItem(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam);

/* Copy WM_MEASUREITEM results back from ARM memory to native struct. */
void MarshalMeasureItemWriteback(LPARAM native_lParam, EmulatedMemory& emem);
