#define NOMINMAX
#include "host_resource.h"

#include "../core/cerf_emulator.h"

REGISTER_SERVICE(HostResource);

std::span<const uint8_t> HostResource::Bytes(const wchar_t* name) const {
    HMODULE hmod = GetModuleHandleW(nullptr);
    HRSRC   hr   = FindResourceW(hmod, name, RT_RCDATA);
    if (!hr) return {};

    HGLOBAL res  = LoadResource(hmod, hr);
    void*   data = res ? LockResource(res) : nullptr;
    DWORD   size = SizeofResource(hmod, hr);
    if (!data || size == 0) return {};

    return { static_cast<const uint8_t*>(data), size };
}
