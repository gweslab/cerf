#pragma once

#include "../core/service.h"
#include "peripheral_base.h"

#include <cstdint>
#include <vector>

class ArmMmu;

class PeripheralDispatcher : public Service {
public:
    using Service::Service;

    /* Cache the ArmMmu pointer that the JIT IO helpers read
       io_pending_address from. */
    void OnReady() override;

    /* Reads p->MmioBase/Size and p->FastReader/Writer() to install one
       dispatch entry per peripheral. Custom thunks (peripherals with
       direct-state state access) skip the AutoFast* path. */
    void Register(Peripheral* p);

    bool IsPeripheralAddress(uint32_t addr) const;

    uint8_t  ReadByte (uint32_t addr);
    uint16_t ReadHalf (uint32_t addr);
    uint32_t ReadWord (uint32_t addr);
    uint64_t ReadDword(uint32_t addr);
    void     WriteByte (uint32_t addr, uint8_t  value);
    void     WriteHalf (uint32_t addr, uint16_t value);
    void     WriteWord (uint32_t addr, uint32_t value);
    void     WriteDword(uint32_t addr, uint64_t value);

    static uint8_t  __fastcall JitIoReadByte (int8_t* hint, PeripheralDispatcher* d);
    static uint16_t __fastcall JitIoReadHalf (int8_t* hint, PeripheralDispatcher* d);
    static uint32_t __fastcall JitIoReadWord (int8_t* hint, PeripheralDispatcher* d);
    static void     __fastcall JitIoWriteByte(int8_t* hint, PeripheralDispatcher* d, uint8_t  value);
    static void     __fastcall JitIoWriteHalf(int8_t* hint, PeripheralDispatcher* d, uint16_t value);
    static void     __fastcall JitIoWriteWord(int8_t* hint, PeripheralDispatcher* d, uint32_t value);

    uint32_t* LastGuestPcPtr() { return &last_guest_pc_; }

private:
    struct Entry {
        uint32_t                base;
        uint32_t                end;      /* exclusive */
        Peripheral::FastReadFn  read;
        Peripheral::FastWriteFn write;
        void*                   ctx;
        /* For 64-bit ReadDword/WriteDword which can't fit through the
           FastReadFn/FastWriteFn signatures. Host-side only — JIT
           never emits 64-bit MMIO. */
        Peripheral*             p;
    };

    std::vector<Entry> entries_;

    ArmMmu*  mmu_           = nullptr;
    uint32_t last_guest_pc_ = 0;

    Entry* LookupEntry(uint32_t addr) const;
};
