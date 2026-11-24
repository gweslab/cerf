#pragma once

#include <windows.h>

typedef BOOL   (WINAPI* PFN_CerfWp7LockPages)(LPVOID, DWORD, PDWORD, int);
typedef HANDLE (WINAPI* PFN_CerfWp7CreateSemaphoreW)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR);
typedef BOOL   (WINAPI* PFN_CerfWp7ReleaseSemaphore)(HANDLE, LONG, LPLONG);
typedef DWORD  (WINAPI* PFN_CerfWp7CallerVm)(void);
typedef LPVOID (WINAPI* PFN_CerfWp7VirtualAllocEx)(HANDLE, LPVOID, DWORD, DWORD, DWORD);
typedef BOOL   (WINAPI* PFN_CerfWp7VirtualCopyEx)(HANDLE, LPVOID, HANDLE, LPVOID, DWORD, DWORD);
typedef BOOL   (WINAPI* PFN_CerfWp7VirtualFreeEx)(HANDLE, LPVOID, DWORD, DWORD);
typedef HRESULT (WINAPI* PFN_CerfWp7ChassisRank)(DWORD*);

typedef struct {
    PFN_CerfWp7LockPages        lock_pages;
    PFN_CerfWp7CreateSemaphoreW create_semaphore;
    PFN_CerfWp7ReleaseSemaphore release_semaphore;
    PFN_CerfWp7CallerVm         caller_vm;
    PFN_CerfWp7VirtualAllocEx   virtual_alloc_ex;
    PFN_CerfWp7VirtualCopyEx    virtual_copy_ex;
    PFN_CerfWp7VirtualFreeEx    virtual_free_ex;
    PFN_CerfWp7ChassisRank      chassis_rank;
} CerfWp7Coredll;

const CerfWp7Coredll* CerfWp7Api(void);
