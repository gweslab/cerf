/* System info thunks: SystemParametersInfoW, KernelIoControl, GetVersionExW,
   GlobalMemoryStatus, GetSystemInfo */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <algorithm>

void Win32Thunks::RegisterSysInfoHandlers() {
    Thunk("GetSystemInfo", 542, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            uint32_t p = regs[0];
            /* WinCE SYSTEM_INFO (36 bytes):
               +0  wProcessorArchitecture(W) + wReserved(W) = dwOemId
               +4  dwPageSize
               +8  lpMinimumApplicationAddress (32-bit ptr)
               +12 lpMaximumApplicationAddress (32-bit ptr)
               +16 dwActiveProcessorMask
               +20 dwNumberOfProcessors
               +24 dwProcessorType
               +28 dwAllocationGranularity
               +32 wProcessorLevel (WORD)
               +34 wProcessorRevision (WORD) */
            mem.Write32(p+0,  5);           /* PROCESSOR_ARCHITECTURE_ARM */
            mem.Write32(p+4,  0x1000);      /* dwPageSize = 4KB (WinCE standard) */
            mem.Write32(p+8,  0x10000);     /* lpMinimumApplicationAddress */
            mem.Write32(p+12, 0x7FFFFFFF);  /* lpMaximumApplicationAddress */
            mem.Write32(p+16, 1);           /* dwActiveProcessorMask */
            mem.Write32(p+20, 1);           /* dwNumberOfProcessors */
            mem.Write32(p+24, 2577);        /* dwProcessorType = PROCESSOR_ARM_7TDMI (2577) */
            mem.Write32(p+28, 0x10000);     /* dwAllocationGranularity = 64KB */
            mem.Write16(p+32, 5);           /* wProcessorLevel = ARMv5 */
            mem.Write16(p+34, 0);           /* wProcessorRevision */
            LOG(API, "[API] GetSystemInfo -> ARM, 1 CPU, page=4096\n");
        }
        regs[0] = 1; return true;
    });
    /* Version/info — configurable via cerf.ini / CLI */
    Thunk("GetVersionExW", 717, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            mem.Write32(regs[0]+4,  os_major);   /* dwMajorVersion */
            mem.Write32(regs[0]+8,  os_minor);   /* dwMinorVersion */
            mem.Write32(regs[0]+12, os_build);   /* dwBuildNumber */
            mem.Write32(regs[0]+16, 0);          /* dwPlatformId (VER_PLATFORM_WIN32_CE=3, but WinCE apps expect 0) */
            /* szCSDVersion at offset 20 (128 wchars) — write build date string */
            std::string date_str = "Built " + os_build_date;
            for (size_t j = 0; j < date_str.size() && j < 127; j++)
                mem.Write16(regs[0] + 20 + (uint32_t)(j * 2), (uint16_t)date_str[j]);
            mem.Write16(regs[0] + 20 + (uint32_t)(date_str.size() * 2), 0);
        }
        LOG(API, "[API] GetVersionExW -> %u.%u build %u (%s)\n",
            os_major, os_minor, os_build, os_build_date.c_str());
        regs[0] = 1; return true;
    });
    ThunkOrdinal("SystemParametersInfoW", 5403); /* WinCE 7 aygshell uses this ordinal */
    Thunk("SystemParametersInfoW", 89, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        UINT uiAction = regs[0], uiParam = regs[1];
        uint32_t pvParam = regs[2];
        UINT fWinIni = regs[3];
        if (uiAction == SPI_GETWORKAREA && pvParam) {
            uint32_t w = fake_screen_resolution ? screen_width : (uint32_t)GetSystemMetrics(SM_CXSCREEN);
            uint32_t h = fake_screen_resolution ? screen_height : (uint32_t)GetSystemMetrics(SM_CYSCREEN);
            mem.Write32(pvParam + 0,  0);    /* left */
            mem.Write32(pvParam + 4,  0);    /* top */
            mem.Write32(pvParam + 8,  w);    /* right */
            mem.Write32(pvParam + 12, h);    /* bottom */
            LOG(API, "[API] SystemParametersInfoW(SPI_GETWORKAREA) -> {0,0,%d,%d}\n", w, h);
            regs[0] = 1;
        } else if (uiAction == 0xE1 /* WinCE 7 SPI_GETSIPINFO via aygshell */ && pvParam) {
            /* WinCE Soft Input Panel info. Fill SIPINFO struct:
               cbSize(4) fdwFlags(4) rcVisibleDesktop(16) rcSipRect(16)
               dwImDataSize(4) pvImData(4) = 48 bytes.
               Report SIP as hidden, visible desktop = full work area. */
            mem.Write32(pvParam + 0,  48);    /* cbSize */
            mem.Write32(pvParam + 4,  0x2);   /* fdwFlags = SIPF_DOCKED (not SIPF_ON) */
            /* rcVisibleDesktop */
            uint32_t sw = fake_screen_resolution ? screen_width : (uint32_t)GetSystemMetrics(SM_CXSCREEN);
            uint32_t sh = fake_screen_resolution ? screen_height : (uint32_t)GetSystemMetrics(SM_CYSCREEN);
            mem.Write32(pvParam + 8,  0);     /* left */
            mem.Write32(pvParam + 12, 0);     /* top */
            mem.Write32(pvParam + 16, sw);    /* right */
            mem.Write32(pvParam + 20, sh);    /* bottom */
            /* rcSipRect = empty (SIP hidden) */
            mem.Write32(pvParam + 24, 0);
            mem.Write32(pvParam + 28, 0);
            mem.Write32(pvParam + 32, 0);
            mem.Write32(pvParam + 36, 0);
            mem.Write32(pvParam + 40, 0);  /* dwImDataSize */
            mem.Write32(pvParam + 44, 0);  /* pvImData */
            LOG(API, "[API] SystemParametersInfoW(0x%X/SPI_GETSIPINFO) -> vis={0,0,%d,%d}\n",
                uiAction, screen_width, screen_height);
            regs[0] = 1;
        } else if (uiAction == SPI_SETDESKWALLPAPER) {
            /* WinCE apps set wallpaper via SPI and expect WM_SETTINGCHANGE broadcast.
               The wallpaper path is a WinCE VFS path in ARM memory — don't forward to native. */
            std::wstring wp_path;
            if (pvParam) wp_path = ReadWStringFromEmu(mem, pvParam);
            LOG(API, "[API] SystemParametersInfoW(SPI_SETDESKWALLPAPER, '%ls')\n", wp_path.c_str());
            /* Broadcast WM_SETTINGCHANGE so the desktop reloads the wallpaper from registry */
            if (fWinIni & SPIF_SENDCHANGE)
                SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETDESKWALLPAPER, 0);
            regs[0] = 1;
        } else if (uiAction == 0x0101 /* SPI_GETPLATFORMTYPE */ && pvParam && uiParam > 0) {
            const wchar_t* plat = L"PocketPC";
            size_t len = wcslen(plat);
            uint32_t max_chars = uiParam;
            for (size_t i = 0; i < len && i < max_chars - 1; i++)
                mem.Write16(pvParam + (uint32_t)(i * 2), (uint16_t)plat[i]);
            mem.Write16(pvParam + (uint32_t)(std::min(len, (size_t)(max_chars - 1)) * 2), 0);
            LOG(API, "[API] SystemParametersInfoW(SPI_GETPLATFORMTYPE) -> '%ls'\n", plat);
            regs[0] = 1;
        } else if (uiAction == 0x0108 /* SPI_GETOEMINFO */ && pvParam && uiParam > 0) {
            const wchar_t* oem = L"CERF Emulator";
            size_t len = wcslen(oem);
            uint32_t max_chars = uiParam;
            for (size_t i = 0; i < len && i < max_chars - 1; i++)
                mem.Write16(pvParam + (uint32_t)(i * 2), (uint16_t)oem[i]);
            mem.Write16(pvParam + (uint32_t)(std::min(len, (size_t)(max_chars - 1)) * 2), 0);
            LOG(API, "[API] SystemParametersInfoW(SPI_GETOEMINFO) -> '%ls'\n", oem);
            regs[0] = 1;
        } else {
            regs[0] = SystemParametersInfoW(uiAction, uiParam, NULL, fWinIni);
        }
        return true;
    });
    Thunk("GlobalMemoryStatus", 88, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t ptr = regs[0];
        if (ptr) {
            MEMORYSTATUS ms = {}; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
            /* Cap at 2GB to stay positive when ARM code interprets as signed int32_t.
               WinCE devices had 32-256MB anyway, so this is generous. */
            const SIZE_T MAX_MEM = 0x7FFFFFFF;
            uint32_t total_phys = (uint32_t)std::min(ms.dwTotalPhys, MAX_MEM);
            uint32_t avail_phys = (uint32_t)std::min(ms.dwAvailPhys, MAX_MEM);
            if (fake_total_phys > 0) {
                /* Scale available proportionally to fake total */
                double ratio = (double)fake_total_phys / (double)total_phys;
                total_phys = fake_total_phys;
                avail_phys = (uint32_t)(avail_phys * ratio);
                if (avail_phys > total_phys) avail_phys = total_phys;
            }
            mem.Write32(ptr+0,  32);
            mem.Write32(ptr+4,  ms.dwMemoryLoad);
            mem.Write32(ptr+8,  total_phys);
            mem.Write32(ptr+12, avail_phys);
            mem.Write32(ptr+16, total_phys);  /* page file = same as phys on WinCE */
            mem.Write32(ptr+20, avail_phys);
            mem.Write32(ptr+24, total_phys);  /* virtual = same as phys on WinCE */
            mem.Write32(ptr+28, avail_phys);
            LOG(API, "[API] GlobalMemoryStatus -> total=%u MB, avail=%u MB%s\n",
                total_phys / (1024*1024), avail_phys / (1024*1024),
                fake_total_phys > 0 ? " (fake)" : "");
        }
        return true;
    });
    /* KernelIoControl — WinCE kernel I/O control interface.
       Used by device property dialogs to query processor name, OEM info, etc.
       via IOCTL_HAL_GET_DEVICE_INFO and similar control codes. */
    Thunk("KernelIoControl", 557, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dwIoControlCode = regs[0];
        uint32_t lpInBuf = regs[1], nInBufSize = regs[2];
        uint32_t lpOutBuf = regs[3];
        uint32_t nOutBufSize = ReadStackArg(regs, mem, 0);
        uint32_t lpBytesReturned = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] KernelIoControl(ioctl=0x%X, inBuf=0x%X, inSize=%u, outBuf=0x%X, outSize=%u) -> stub\n",
            dwIoControlCode, lpInBuf, nInBufSize, lpOutBuf, nOutBufSize);

        /* IOCTL_PROCESSOR_INFORMATION = 0x01010064 (CTL_CODE(FILE_DEVICE_HAL, 25, ...))
           Returns PROCESSOR_INFO struct (576 bytes):
           +0   wVersion (WORD)
           +2   szProcessCore[40] (80 bytes, WCHAR)
           +82  wCoreRevision (WORD)
           +84  szProcessorName[40] (80 bytes, WCHAR)
           +164 wProcessorRevision (WORD)
           +166 szCatalogNumber[100] (200 bytes, WCHAR)
           +366 szVendor[100] (200 bytes, WCHAR)
           +566 dwInstructionSet (DWORD)
           +570 dwClockSpeed (DWORD) */
        if (dwIoControlCode == 0x01010064 && lpOutBuf && nOutBufSize >= 576) {
            /* Zero-fill first */
            for (uint32_t i = 0; i < 576; i += 4) mem.Write32(lpOutBuf + i, 0);
            mem.Write16(lpOutBuf + 0, 1); /* wVersion */
            /* szProcessCore */
            const wchar_t* core = L"ARMv5TEJ";
            for (size_t i = 0; i <= wcslen(core); i++)
                mem.Write16(lpOutBuf + 2 + (uint32_t)(i * 2), (uint16_t)core[i]);
            mem.Write16(lpOutBuf + 82, 5); /* wCoreRevision */
            /* szProcessorName */
            const wchar_t* name = L"ARM920T";
            for (size_t i = 0; i <= wcslen(name); i++)
                mem.Write16(lpOutBuf + 84 + (uint32_t)(i * 2), (uint16_t)name[i]);
            mem.Write16(lpOutBuf + 164, 0); /* wProcessorRevision */
            /* szVendor */
            const wchar_t* vendor = L"ARM Ltd.";
            for (size_t i = 0; i <= wcslen(vendor); i++)
                mem.Write16(lpOutBuf + 366 + (uint32_t)(i * 2), (uint16_t)vendor[i]);
            mem.Write32(lpOutBuf + 566, 5); /* dwInstructionSet = ARMv5 */
            mem.Write32(lpOutBuf + 570, 400); /* dwClockSpeed = 400 MHz */
            if (lpBytesReturned) mem.Write32(lpBytesReturned, 576);
            LOG(API, "[API] KernelIoControl(IOCTL_PROCESSOR_INFORMATION) -> ARM920T\n");
            regs[0] = 1;
        }
        /* IOCTL_HAL_GET_DEVICE_INFO = 0x01010004 */
        else if (dwIoControlCode == 0x01010004 && lpOutBuf && nOutBufSize >= 2) {
            const wchar_t* info = L"CERF Emulator";
            size_t len = wcslen(info);
            uint32_t bytes = (uint32_t)((len + 1) * 2);
            if (bytes <= nOutBufSize) {
                for (size_t i = 0; i <= len; i++)
                    mem.Write16(lpOutBuf + (uint32_t)(i * 2), (uint16_t)info[i]);
                if (lpBytesReturned) mem.Write32(lpBytesReturned, bytes);
                regs[0] = 1;
            } else {
                regs[0] = 0;
            }
        } else {
            regs[0] = 0; /* Not handled */
        }
        return true;
    });
}
