#pragma once

#include "rom_parser_service.h"

#include "../core/service.h"

#include <cstdint>
#include <span>

class RomParserQueries : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void OnReady() override;

    /* The primary partition's kernel module (nk.exe). Null if absent. */
    const ParsedTOCentry* KernelModule() const;

    /* Slice of bytes covering kernel-VA [va, va+len), searching every
       loaded partition. Empty span if no partition's flat range covers
       the request. */
    std::span<const uint8_t> ReadVa(uint32_t va, uint32_t len) const;

    /* Bytes of a module by name (case-insensitive), searching every
       loaded partition's TOC. Returns the e32_rom.vsize-sized span
       starting at the module's ulLoadOffset; empty when not found. */
    std::span<const uint8_t> ModuleBytesByName(const char* name) const;

    bool KernelSubsystemVersion(uint16_t& major, uint16_t& minor) const;

private:
    const std::vector<ParsedRom>& Loaded() const;
};
