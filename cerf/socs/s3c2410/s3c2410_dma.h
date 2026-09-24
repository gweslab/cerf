#pragma once

#include "../../peripherals/peripheral_base.h"

#include <array>
#include <cstdint>
#include <mutex>

/* S3C2410A User Manual, printed p. 8-2, Table 8-1 "DMA Request Sources for Each
   Channel". */
enum class S3C2410DmaSource : uint8_t {
    kXdreq0,
    kXdreq1,
    kUart0,
    kUart1,
    kUart2,
    kSdi,
    kSpi0,
    kSpi1,
    kI2sSdo,
    kI2sSdi,
    kTimer,
    kUsbEp1,
    kUsbEp2,
    kUsbEp3,
    kUsbEp4,
};

class S3C2410DmaRequester {
public:
    virtual ~S3C2410DmaRequester() = default;
    virtual void OnDmaChannelArmed() = 0;
};

class S3C2410Dma : public Peripheral {
public:
    using Peripheral::Peripheral;

    void RegisterRequester(S3C2410DmaSource source, S3C2410DmaRequester* r);

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x4B000000u; }
    uint32_t MmioSize() const override { return 0xE4u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState   (StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore () override;

    /* S3C2410A User Manual, printed p. 8-2 "DMA OPERATION". */
    bool ServiceRequest(S3C2410DmaSource source);

private:
    struct Channel {
        uint32_t disrc    = 0;
        uint32_t disrcc   = 0;
        uint32_t didst    = 0;
        uint32_t didstc   = 0;
        uint32_t dcon     = 0;
        uint32_t mask     = 0;
        uint32_t curr_src = 0;
        uint32_t curr_dst = 0;
        uint32_t curr_tc  = 0;

        template <typename F>
        static constexpr void Visit(Channel& c, F& field) {
            field("disrc", c.disrc);
            field("disrcc", c.disrcc);
            field("didst", c.didst);
            field("didstc", c.didstc);
            field("dcon", c.dcon);
            field("mask", c.mask);
            field("curr_src", c.curr_src);
            field("curr_dst", c.curr_dst);
            field("curr_tc", c.curr_tc);
        }
    };

    static constexpr uint32_t kChannelCount   = 4u;
    static constexpr uint32_t kRequesterCount =
        static_cast<uint32_t>(S3C2410DmaSource::kUsbEp4) + 1u;

    S3C2410DmaSource  ChannelSource(uint32_t n, const Channel& c);
    S3C2410DmaRequester* RequesterFor(S3C2410DmaSource source) const;

    void Reset();
    bool RunChannelLocked    (uint32_t n, Channel& c);
    bool SelfReferential(uint32_t pa) const {
        return pa >= MmioBase() && pa < MmioBase() + MmioSize();
    }
    bool RunAtomicLocked     (Channel& c);
    void LoadLocked          (Channel& c);
    void TerminalCountLocked (uint32_t n, Channel& c);

    std::mutex                                             mutex_;
    std::array<Channel, kChannelCount>                     ch_{};
    std::array<S3C2410DmaRequester*, kRequesterCount>      requesters_{};
};
