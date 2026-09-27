#pragma once

#include "cerf_fs_protocol.h"

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL (*SHELLFILECHANGEFUNC_t)(void* pfci);

typedef struct CerfVol {
    int iAFS;
} CerfVol;

typedef struct CerfFile {
    unsigned short fHandle;
    unsigned long  pos;
} CerfFile;

typedef struct CerfFind {
    unsigned long tid;
} CerfFind;

void CerfFsAfsInit(void);

void   CerfFsNotifyInit(void);

HANDLE CerfFsFindFirstChangeNotificationW(CerfVol* vol, HANDLE hProc, PCWSTR path,
                                          BOOL subtree, DWORD filter);

HANDLE CerfFsFileApi(void);
HANDLE CerfFsFindApi(void);
BOOL   CerfFsSeekTakesOffset(void);

HANDLE CerfFsMakeHandle(HANDLE apiSet, void* ctx, HANDLE hProc);

volatile CerfFsChannel* CerfFsMapChannel(void);

unsigned long CerfFsCall(CerfFsServerPB* pb, unsigned long code);

CerfFsServerPB* CerfFsPb(void);
unsigned char*  CerfFsIoBuf(void);
void            CerfFsLock(void);
void            CerfFsUnlock(void);

int CerfFsResultToBool(unsigned long result);

void CerfFsDosToFiletime(unsigned long dos_datetime, FILETIME* out);

BOOL   CerfFsCloseVolume(CerfVol* vol);
BOOL   CerfFsCreateDirectoryW(CerfVol* vol, PCWSTR path, LPSECURITY_ATTRIBUTES sa);
BOOL   CerfFsRemoveDirectoryW(CerfVol* vol, PCWSTR path);
DWORD  CerfFsGetFileAttributesW(CerfVol* vol, PCWSTR name);
BOOL   CerfFsSetFileAttributesW(CerfVol* vol, PCWSTR name, DWORD attrs);
HANDLE CerfFsCreateFileW(CerfVol* vol, HANDLE hProc, PCWSTR name, DWORD access,
                         DWORD share, PSECURITY_ATTRIBUTES sa, DWORD create,
                         DWORD flags, HANDLE templ);
BOOL   CerfFsDeleteFileW(CerfVol* vol, PCWSTR name);
BOOL   CerfFsMoveFileW(CerfVol* vol, PCWSTR oldn, PCWSTR newn);
HANDLE CerfFsFindFirstFileW(CerfVol* vol, HANDLE hProc, PCWSTR spec,
                            PWIN32_FIND_DATAW fd);
BOOL   CerfFsDeleteAndRenameFileW(CerfVol* vol, PCWSTR oldn, PCWSTR newn);
BOOL   CerfFsCloseAllFiles(CerfVol* vol, HANDLE hProc);
BOOL   CerfFsGetDiskFreeSpaceW(CerfVol* vol, PCWSTR path,
                               PDWORD pSectorsPerCluster, PDWORD pBytesPerSector,
                               PDWORD pFreeClusters, PDWORD pClusters);
void   CerfFsNotify(CerfVol* vol, DWORD dwFlags);
BOOL   CerfFsRegisterFileSystemFunction(CerfVol* vol, SHELLFILECHANGEFUNC_t pfn);

BOOL  CerfFsCloseFile(CerfFile* f);
BOOL  CerfFsReadFile(CerfFile* f, PVOID buf, DWORD count, PDWORD done, OVERLAPPED* ov);
BOOL  CerfFsWriteFile(CerfFile* f, const void* buf, DWORD count, PDWORD done, OVERLAPPED* ov);
DWORD CerfFsGetFileSize(CerfFile* f, PDWORD sizeHigh);
DWORD CerfFsSetFilePointer(CerfFile* f, LONG dist, PLONG distHigh, DWORD method);
BOOL  CerfFsGetFileInformationByHandle(CerfFile* f, PBY_HANDLE_FILE_INFORMATION fi);
BOOL  CerfFsFlushFileBuffers(CerfFile* f);
BOOL  CerfFsGetFileTime(CerfFile* f, FILETIME* create, FILETIME* access, FILETIME* write);
BOOL  CerfFsSetFileTime(CerfFile* f, const FILETIME* create, const FILETIME* access,
                        const FILETIME* write);
BOOL  CerfFsSetEndOfFile(CerfFile* f);
BOOL  CerfFsFileIoControl(CerfFile* f, DWORD code, PVOID pIn, DWORD inLen,
                          PVOID pOut, DWORD outLen, PDWORD pActualOut,
                          OVERLAPPED* ov);
BOOL  CerfFsReadFileWithSeek(CerfFile* f, PVOID buf, DWORD count, PDWORD done,
                             OVERLAPPED* ov, DWORD low, DWORD high);
BOOL  CerfFsWriteFileWithSeek(CerfFile* f, const void* buf, DWORD count, PDWORD done,
                              OVERLAPPED* ov, DWORD low, DWORD high);

BOOL CerfFsFindClose(CerfFind* s);
BOOL CerfFsFindNextFileW(CerfFind* s, PWIN32_FIND_DATAW fd);

#ifdef __cplusplus
}
#endif
