/* Window thunks: Get/SetWindowLong, text, rect ops */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterWindowPropsHandlers() {
    Thunk("SetRect", 103, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        mem.Write32(regs[0], regs[1]); mem.Write32(regs[0]+4, regs[2]);
        mem.Write32(regs[0]+8, regs[3]); mem.Write32(regs[0]+12, ReadStackArg(regs,mem,0));
        regs[0] = 1; return true;
    });
    Thunk("CopyRect", 96, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, mem.Read32(regs[1]+i*4));
        regs[0] = 1; return true;
    });
    Thunk("SetRectEmpty", 104, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, 0); regs[0] = 1; return true;
    });
    Thunk("InflateRect", 98, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        int32_t dx=(int32_t)regs[1],dy=(int32_t)regs[2];
        mem.Write32(regs[0],l-dx); mem.Write32(regs[0]+4,t-dy); mem.Write32(regs[0]+8,r+dx); mem.Write32(regs[0]+12,b+dy);
        regs[0]=1; return true;
    });
    Thunk("OffsetRect", 101, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        OffsetRect(&rc,(int)regs[1],(int)regs[2]);
        mem.Write32(regs[0],rc.left); mem.Write32(regs[0]+4,rc.top);
        mem.Write32(regs[0]+8,rc.right); mem.Write32(regs[0]+12,rc.bottom);
        regs[0]=1; return true;
    });
    Thunk("IntersectRect", 99, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = IntersectRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top);
        mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("UnionRect", 106, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = UnionRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top); mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("PtInRect", 102, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        POINT pt={(LONG)regs[1],(LONG)regs[2]}; regs[0]=PtInRect(&rc,pt); return true;
    });
    Thunk("IsRectEmpty", 100, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        regs[0]=(r<=l||b<=t)?1:0; return true;
    });
    Thunk("EqualRect", 97, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        bool eq=true; for(int i=0;i<4;i++) if(mem.Read32(regs[0]+i*4)!=mem.Read32(regs[1]+i*4)) eq=false;
        regs[0]=eq?1:0; return true;
    });
    Thunk("SubtractRect", 105, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=0; return true; });
    Thunk("GetWindowRect", 248, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        RECT rc; BOOL ret=GetWindowRect(hw,&rc);
        /* No deflation needed — windows are WS_POPUP with WinCE NC area handled by
           our WM_NCCALCSIZE, so native rect IS the WinCE rect. Pass through as-is. */
        mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top);
        mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom);
        regs[0]=ret; return true;
    });
    Thunk("GetClientRect", 249, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        RECT rc; BOOL ret=GetClientRect(hw,&rc);
        mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top);
        mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom);
        regs[0]=ret; return true;
    });
    Thunk("InvalidateRect", 250, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        RECT*prc=NULL; RECT rc;
        if(regs[1]){rc.left=mem.Read32(regs[1]);rc.top=mem.Read32(regs[1]+4);rc.right=mem.Read32(regs[1]+8);rc.bottom=mem.Read32(regs[1]+12);prc=&rc;}
        BOOL ret = InvalidateRect(hw,prc,regs[2]);
        wchar_t _irc[64]={}; if(hw) GetClassNameW(hw,_irc,64);
        LOG(API, "[API] InvalidateRect(0x%p '%ls', %s, %d) -> %d\n", hw, _irc,
            prc ? "rect" : "NULL", regs[2], ret);
        regs[0]=ret; return true;
    });
    Thunk("ValidateRect", 278, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=ValidateRect((HWND)(intptr_t)(int32_t)regs[0],NULL); return true; });
    Thunk("GetUpdateRect", 274, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; BOOL ret=GetUpdateRect((HWND)(intptr_t)(int32_t)regs[0],&rc,regs[2]);
        if(regs[1]){mem.Write32(regs[1],rc.left);mem.Write32(regs[1]+4,rc.top);mem.Write32(regs[1]+8,rc.right);mem.Write32(regs[1]+12,rc.bottom);}
        regs[0]=ret; return true;
    });
    Thunk("GetParent", 269, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=(uint32_t)(uintptr_t)GetParent((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("IsWindow", 271, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindow((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("IsWindowVisible", 886, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindowVisible((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("EnableWindow", 287, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=EnableWindow((HWND)(intptr_t)(int32_t)regs[0],regs[1]); return true; });
    Thunk("IsWindowEnabled", 288, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindowEnabled((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("SetWindowTextW", 256, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0]=SetWindowTextW((HWND)(intptr_t)(int32_t)regs[0], ReadWStringFromEmu(mem,regs[1]).c_str()); return true;
    });
    Thunk("GetWindowLongW", 259, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int idx = (int)regs[1];
        if (idx == -4 /* GWL_WNDPROC */) {
            auto it = hwnd_wndproc_map.find(hw);
            regs[0] = (it != hwnd_wndproc_map.end()) ? it->second : 0;
            LOG(API, "[API] GetWindowLongW(%p, GWL_WNDPROC) -> 0x%08X\n", hw, regs[0]);
            return true;
        }
        /* GWL_STYLE: return original WinCE style (not the WS_POPUP we converted to) */
        if (idx == GWL_STYLE) {
            auto sit = hwnd_wce_style_map.find(hw);
            if (sit != hwnd_wce_style_map.end()) {
                regs[0] = sit->second;
                LOG(API, "[API] GetWindowLongW(%p, GWL_STYLE) -> 0x%08X (WinCE map)\n", hw, regs[0]);
                return true;
            }
        }
        /* GWL_EXSTYLE: return original WinCE extended style */
        if (idx == GWL_EXSTYLE) {
            auto eit = hwnd_wce_exstyle_map.find(hw);
            if (eit != hwnd_wce_exstyle_map.end()) {
                regs[0] = eit->second;
                LOG(API, "[API] GetWindowLongW(%p, GWL_EXSTYLE) -> 0x%08X (WinCE map)\n", hw, regs[0]);
                return true;
            }
            LONG val = GetWindowLongW(hw, idx);
            if (captionok_hwnds.count(hw))
                val |= (LONG)0x80000000;
            regs[0] = (uint32_t)val;
            LOG(API, "[API] GetWindowLongW(%p, GWL_EXSTYLE) -> 0x%08X\n", hw, regs[0]);
            return true;
        }
        /* WinCE dialog extra data: translate 32-bit offsets to 64-bit */
        if (idx >= 0 && idx <= 8 && hwnd_dlgproc_map.count(hw)) {
            if (idx == 8)       regs[0] = (uint32_t)GetWindowLongPtrW(hw, DWLP_USER);
            else if (idx == 4)  regs[0] = hwnd_dlgproc_map[hw];
            else                regs[0] = (uint32_t)GetWindowLongPtrW(hw, DWLP_MSGRESULT);
            LOG(API, "[API] GetWindowLongW(%p, %d) -> 0x%08X (dialog extra)\n", hw, idx, regs[0]);
        } else {
            regs[0] = (uint32_t)GetWindowLongW(hw, idx);
            LOG(API, "[API] GetWindowLongW(%p, %d) -> 0x%08X\n", hw, idx, regs[0]);
        }
        return true;
    });
    Thunk("SetWindowLongW", 258, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int idx = (int)regs[1];
        LONG nv = (LONG)regs[2];
        /* GWL_WNDPROC: ARM code is changing the window's WndProc to a new ARM address.
           Update our map instead of calling native SetWindowLongW (which would corrupt
           the native WndProc pointer on x64, and also fails for GWL_WNDPROC on x64). */
        if (idx == -4 /* GWL_WNDPROC */) {
            auto it = hwnd_wndproc_map.find(hw);
            regs[0] = (it != hwnd_wndproc_map.end()) ? it->second : 0;
            if (nv) {
                hwnd_wndproc_map[hw] = (uint32_t)nv;
                /* If this HWND was a dialog (native WNDPROC = DefDlgProc), switch its
                   native WNDPROC to EmuWndProc so messages route through the ARM WndProc
                   chain instead of the dialog proc chain.  MFC does this to subclass
                   dialog-based main windows. */
                SetWindowLongPtrW(hw, GWLP_WNDPROC, (LONG_PTR)EmuWndProc);
                LOG(API, "[API] SetWindowLongW(0x%p, GWL_WNDPROC, 0x%08X) -> old=0x%08X\n",
                    hw, (uint32_t)nv, regs[0]);
            }
            return true;
        }
        if (idx == GWL_STYLE) {
            /* ARM code is changing the window style — update our WinCE style map
               and return the old WinCE style.  Don't pass to native SetWindowLongW
               because our window is WS_POPUP and the ARM style has WS_CAPTION etc. */
            auto sit = hwnd_wce_style_map.find(hw);
            if (sit != hwnd_wce_style_map.end()) {
                regs[0] = sit->second;
                sit->second = (uint32_t)nv;
                LOG(API, "[API] SetWindowLongW(%p, GWL_STYLE, 0x%08X) -> old=0x%08X (WinCE map)\n",
                    hw, (uint32_t)nv, regs[0]);
                /* Trigger NC recalculation if caption state changed */
                SetWindowPos(hw, NULL, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
                return true;
            }
        }
        if (idx == GWL_EXSTYLE) {
            /* Update WinCE exstyle map */
            auto eit = hwnd_wce_exstyle_map.find(hw);
            if (eit != hwnd_wce_exstyle_map.end()) {
                regs[0] = eit->second;
                eit->second = (uint32_t)nv;
            }
            if (nv & (LONG)0x80000000) {
                if (captionok_hwnds.insert(hw).second) InstallCaptionOk(hw);
            } else {
                if (captionok_hwnds.erase(hw)) RemoveCaptionOk(hw);
            }
            nv &= 0x0FFFFFFF;
        }
        /* Translate WinCE 32-bit dialog extra data offsets to 64-bit */
        if (idx >= 0 && idx <= 8 && hwnd_dlgproc_map.count(hw)) {
            if (idx == 8) {
                regs[0] = (uint32_t)SetWindowLongPtrW(hw, DWLP_USER, (LONG_PTR)(int32_t)nv);
                LOG(API, "[API] SetWindowLongW(%p, DWL_USER=8, 0x%08X) -> old=0x%08X (dialog extra)\n",
                    hw, (uint32_t)nv, regs[0]);
            } else if (idx == 4) {
                /* DWL_DLGPROC: ARM code setting a new dialog proc — update our map
                   instead of corrupting the native DLGPROC pointer */
                regs[0] = (uint32_t)hwnd_dlgproc_map[hw];
                if (nv) {
                    hwnd_dlgproc_map[hw] = (uint32_t)nv;
                    LOG(API, "[API] SetWindowLongW(0x%p, DWL_DLGPROC, 0x%08X) -> old=0x%08X\n",
                        hw, (uint32_t)nv, regs[0]);
                }
            } else {
                regs[0] = (uint32_t)SetWindowLongPtrW(hw, DWLP_MSGRESULT, (LONG_PTR)(int32_t)nv);
                LOG(API, "[API] SetWindowLongW(%p, DWL_MSGRESULT=%d, 0x%08X) -> old=0x%08X (dialog extra)\n",
                    hw, idx, (uint32_t)nv, regs[0]);
            }
        } else {
            regs[0] = SetWindowLongW(hw, idx, nv);
            LOG(API, "[API] SetWindowLongW(%p, %d, 0x%08X) -> old=0x%08X\n", hw, idx, (uint32_t)nv, regs[0]);
        }
        return true;
    });
    Thunk("GetWindowTextW", 257, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[1024]={}; uint32_t mx=regs[2]; if(mx>1024)mx=1024;
        int ret=GetWindowTextW((HWND)(intptr_t)(int32_t)regs[0],buf,mx);
        for(int i=0;i<=ret;i++) mem.Write16(regs[1]+i*2,buf[i]);
        regs[0]=ret; return true;
    });
    Thunk("GetWindowTextLengthW", 276, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0]=GetWindowTextLengthW((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("IsChild", 277, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0]=IsChild((HWND)(intptr_t)(int32_t)regs[0],(HWND)(intptr_t)(int32_t)regs[1]); return true;
    });
    Thunk("AdjustWindowRectEx", 887, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]), t=mem.Read32(regs[0]+4);
        int32_t r=mem.Read32(regs[0]+8), b=mem.Read32(regs[0]+12);
        DWORD style = regs[1];
        /* Return WinCE-like frame dimensions (1px border for WS_CAPTION,
           plus caption height) instead of thick desktop frame. */
        int border = (style & WS_CAPTION) ? 1 : 0;
        l -= border; t -= border; r += border; b += border;
        if (style & WS_CAPTION)
            t -= GetSystemMetrics(SM_CYCAPTION);
        mem.Write32(regs[0],l); mem.Write32(regs[0]+4,t);
        mem.Write32(regs[0]+8,r); mem.Write32(regs[0]+12,b);
        regs[0]=1; return true;
    });
}
