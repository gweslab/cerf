/*
 * CEShell.DLL thunks - Windows CE Shell API
 *
 * CEShell provides shell operations: folder browsing, special folder paths,
 * file operations, shortcuts, icon extraction, and COM shell interfaces.
 */
#include "../win32_thunks.h"

void Win32Thunks::RegisterCeshellHandlers() {
    /* SHGetSpecialFolderLocation - get PIDL for special folder
       Returns E_NOTIMPL so apps don't dereference NULL COM pointers */
    Thunk("SHGetSpecialFolderLocation", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetSpecialFolderLocation(hwnd=0x%08X, csidl=%d, ppidl=0x%08X) -> E_NOTIMPL (stub)\n",
               regs[0], regs[1], regs[2]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });

    /* SHGetMalloc - get shell IMalloc interface
       Returns E_NOTIMPL to avoid NULL COM pointer dereference */
    Thunk("SHGetMalloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetMalloc(ppMalloc=0x%08X) -> E_NOTIMPL (stub)\n", regs[0]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });

    /* SHGetPathFromIDList - convert PIDL to filesystem path */
    Thunk("SHGetPathFromIDList", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetPathFromIDList(pidl=0x%08X, pszPath=0x%08X) -> FALSE (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0;
        return true;
    });

    /* SHGetShortcutTarget - resolve .lnk shortcut target */
    Thunk("SHGetShortcutTarget", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetShortcutTarget(pszShortcut=0x%08X, pszTarget=0x%08X, cbMax=%d) -> FALSE (stub)\n",
               regs[0], regs[1], regs[2]);
        regs[0] = 0;
        return true;
    });

    /* SHLoadDIBitmap - load bitmap from file */
    Thunk("SHLoadDIBitmap", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHLoadDIBitmap(pszFileName=0x%08X) -> NULL (stub)\n", regs[0]);
        regs[0] = 0;
        return true;
    });

    /* SHBrowseForFolder - display folder selection dialog */
    Thunk("SHBrowseForFolder", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHBrowseForFolder(lpbi=0x%08X) -> NULL (stub)\n", regs[0]);
        regs[0] = 0; /* NULL PIDL = user cancelled */
        return true;
    });

    /* SHFileOperation - copy/move/rename/delete files */
    Thunk("SHFileOperation", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHFileOperation(lpFileOp=0x%08X) -> ERROR (stub)\n", regs[0]);
        regs[0] = 1; /* non-zero = error */
        return true;
    });

    /* SHGetSpecialFolderPath - get path string for special folder */
    Thunk("SHGetSpecialFolderPath", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetSpecialFolderPath(hwnd=0x%08X, lpszPath=0x%08X, csidl=%d, fCreate=%d) -> FALSE (stub)\n",
               regs[0], regs[1], regs[2], regs[3]);
        regs[0] = 0;
        return true;
    });

    /* SHCreateShortcut - create a .lnk shortcut */
    Thunk("SHCreateShortcut", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHCreateShortcut(pszShortcut=0x%08X, pszTarget=0x%08X) -> FALSE (stub)\n",
               regs[0], regs[1]);
        regs[0] = 0;
        return true;
    });

    /* SHAddToRecentDocs - add file to recent documents list */
    Thunk("SHAddToRecentDocs", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHAddToRecentDocs(uFlags=%d, pv=0x%08X) -> stub\n", regs[0], regs[1]);
        /* void function, no return value */
        return true;
    });

    /* ExtractIconExW - extract icon from executable/DLL */
    Thunk("ExtractIconExW", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] ExtractIconExW(lpszFile=0x%08X, nIconIndex=%d, phiconLarge=0x%08X, phiconSmall=0x%08X) -> 0 (stub)\n",
               regs[0], (int32_t)regs[1], regs[2], regs[3]);
        regs[0] = 0; /* 0 icons extracted */
        return true;
    });

    /* SHGetFileInfo - get info about file/folder */
    Thunk("SHGetFileInfo", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHGetFileInfo(pszPath=0x%08X, dwFileAttributes=0x%08X, psfi=0x%08X, cbFileInfo=%d) -> 0 (stub)\n",
               regs[0], regs[1], regs[2], regs[3]);
        regs[0] = 0;
        return true;
    });

    /* DragAcceptFiles - register window for drag-drop */
    Thunk("DragAcceptFiles", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] DragAcceptFiles(hWnd=0x%08X, fAccept=%d) -> stub\n", regs[0], regs[1]);
        /* void function */
        return true;
    });

    /* SHFreeNameMappings - free name mapping from SHFileOperation */
    Thunk("SHFreeNameMappings", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[THUNK] SHFreeNameMappings(hNameMappings=0x%08X) -> stub\n", regs[0]);
        /* void function */
        return true;
    });
}
