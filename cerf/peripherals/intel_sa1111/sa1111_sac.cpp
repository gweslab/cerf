#include "sa1111_sac.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../peripheral_dispatcher.h"
#include "sa1111_intc.h"
#include "sa1111_system_controller.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/state_stream.h"

bool Sa1111Sac::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111Sac::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

uint32_t Sa1111Sac::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x60u && off <= 0x9Cu) return 0;   /* SADR FIFO drained. */
    switch (off) {
        case 0x00: return sacr0_;
        case 0x04: return sacr1_;
        case 0x08: return sacr2_;
        case 0x0C: return 0x9u | (l3wd_ ? 1u << 16 : 0u)
                               | (l3rd_ ? 1u << 17 : 0u);  /* SASR0. */
        case 0x10: return 0x9u;                            /* SASR1. */
        case 0x1C: return l3car_;
        case 0x20: return l3_regs_[l3car_];
        case 0x24: return accar_;
        case 0x28: return accdr_;
        case 0x2C: return acsar_;
        case 0x30: return 0;          /* ACSDR - no AC-link codec. */
        case 0x34: {
            std::unique_lock<std::mutex> lk(dma_mtx_);
            return sadtcs_;
        }
        case 0x38: return sadtsa_;
        case 0x3C: return sadtca_;
        case 0x40: return sadtsb_;
        case 0x44: return sadtcb_;
        case 0x48: return sadrcs_;
        case 0x4C: return sadrsa_;
        case 0x50: return sadrca_;
        case 0x54: return sadrsb_;
        case 0x58: return sadrcb_;
        case 0x5C: return saitr_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111Sac::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x60u && off <= 0x9Cu) return;     /* SADR FIFO: discard. */
    switch (off) {
        case 0x00: sacr0_ = value; return;
        case 0x04: sacr1_ = value; return;
        case 0x08: sacr2_ = value; return;
        case 0x18:                                /* SASCR, Table 7-12. */
            if (value & (1u << 16)) l3wd_ = false;     /* DTS. */
            if (value & (1u << 17)) l3rd_ = false;     /* RDD. */
            return;
        case 0x1C: l3car_ = value & 0xFFu; return;
        case 0x20:
            l3_regs_[l3car_] = value & 0xFFu;
            l3wd_ = true;
            LOG(Periph, "[Sa1111Sac] L3 codec write addr=0x%02X "
                "val=0x%02X\n", l3car_, value & 0xFFu);
            emu_.Get<Sa1111Intc>().RaiseInterrupt(40);  /* AudDTS. */
            return;
        case 0x24: accar_ = value; return;
        case 0x28: accdr_ = value; return;
        case 0x2C: acsar_ = value; return;
        case 0x34: WriteSadtcs(value); return;
        case 0x38: sadtsa_ = value; return;
        case 0x3C: sadtca_ = value; return;
        case 0x40: sadtsb_ = value; return;
        case 0x44: sadtcb_ = value; return;
        case 0x48:
            /* Receive DMA (recording): paced sample-source not built. */
            if (value & (kTden | kTdsta | kTdstb)) {
                LOG(Caution, "Sa1111Sac: audio DMA receive start "
                    "(SADRCS=0x%08X) is not implemented\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            sadrcs_ = value;
            return;
        case 0x4C: sadrsa_ = value; return;
        case 0x50: sadrca_ = value; return;
        case 0x54: sadrsb_ = value; return;
        case 0x58: sadrcb_ = value; return;
        case 0x5C: saitr_ = value; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* TDSTA/TDSTB are start strobes the engine consumes on pickup; the guest
   re-sets the strobe each time it refills a buffer (wavedev sub_FD5094
   callback) and stops re-setting when out of data, so SADTCS&0xD0 reaches 0
   (sub_FD17C4) and the IST takes its drained path (sub_FD1C74 cause 16). */
void Sa1111Sac::WriteSadtcs(uint32_t value) {
    std::unique_lock<std::mutex> lk(dma_mtx_);
    sadtcs_ &= ~(value & (kTdbda | kTdbdb));      /* done bits W1C. */
    sadtcs_  = (sadtcs_ & ~(kTden | kTdie)) | (value & (kTden | kTdie));
    sadtcs_ |= value & (kTdsta | kTdstb);         /* arm strobes. */
#if CERF_DEV_MODE
    LOG(Periph, "[Sa1111Sac] SADTCS W 0x%08X -> 0x%08X (running=%d buf=%c)\n",
        value, sadtcs_, tx_running_ ? 1 : 0, tx_buffer_b_ ? 'B' : 'A');
#endif
    if (!(sadtcs_ & kTden)) {                     /* wavedev stop. */
        tx_running_ = false;
        sadtcs_ &= ~(kTdsta | kTdstb | kTbiu);
        return;
    }
    if (!tx_running_) TryStartNextLocked(lk);
}

/* Picks an armed buffer, consumes its strobe, hands the page to the player.
   Drops the lock around the sink call (the sink posts to its own thread).
   A declined page completes inline WITHOUT continuing - continuing unpaced
   would recurse submit->complete->submit without bound. */
void Sa1111Sac::TryStartNextLocked(std::unique_lock<std::mutex>& lk) {
    bool b;
    if (sadtcs_ & kTdsta)      b = false;
    else if (sadtcs_ & kTdstb) b = true;
    else { tx_running_ = false; sadtcs_ &= ~kTbiu; return; }

    tx_running_  = true;
    tx_buffer_b_ = b;
    sadtcs_ &= ~(b ? kTdstb : kTdsta);            /* strobe consumed. */
    sadtcs_  = (sadtcs_ & ~kTbiu) | (b ? kTbiu : 0u);   /* Table 7-19 TBIU. */
    TransmitPage page{
        b,
        (b ? sadtsb_ : sadtsa_) & ~0x3u,          /* LSB2 = 00, Table 7-20. */
        (b ? sadtcb_ : sadtca_) & ~0x3u,
        emu_.Get<Sa1111SystemController>().AudioSampleRateHz(),
    };
#if CERF_DEV_MODE
    LOG(Periph, "[Sa1111Sac] TX pickup buf=%c pa=0x%08X bytes=%u rate=%u "
        "SADTCS=0x%08X\n", b ? 'B' : 'A', page.src_pa, page.byte_count,
        page.sample_rate_hz, sadtcs_);
#endif
    lk.unlock();
    if (tx_sink_ && tx_sink_(page)) return;

    LOG(Caution, "Sa1111Sac: transmit page declined by the audio sink - "
        "completing it inline\n");
    CompleteTransmit(b);
}

/* Transmit Done A = source 32, Done B = source 34 (Table 11-1; 33/35 are
   the receive channel). */
void Sa1111Sac::CompleteTransmit(bool buffer_b) {
    bool raise = false, start_next = false;
    {
        std::unique_lock<std::mutex> lk(dma_mtx_);
        if (!tx_running_ || tx_buffer_b_ != buffer_b) return;
        /* Cleared BEFORE the continuation - TryStartNext is gated on
           !tx_running_ in BOTH this thread and a racing WriteSadtcs; clearing
           it only on !start_next wedges the ping-pong after one page. */
        tx_running_ = false;
        sadtcs_ |= buffer_b ? kTdbdb : kTdbda;
        raise = (sadtcs_ & kTdie) != 0;
        start_next = (sadtcs_ & kTden) &&
                     (sadtcs_ & (kTdsta | kTdstb));
        if (!start_next) sadtcs_ &= ~kTbiu;
#if CERF_DEV_MODE
        LOG(Periph, "[Sa1111Sac] TX done buf=%c SADTCS=0x%08X raise=%d "
            "next=%d\n", buffer_b ? 'B' : 'A', sadtcs_, raise ? 1 : 0,
            start_next ? 1 : 0);
#endif
    }
    emu_.Get<AudioActivityWidget>().MarkTx();
    if (raise)
        emu_.Get<Sa1111Intc>().RaiseInterrupt(buffer_b ? 34u : 32u);
    if (start_next) {
        std::unique_lock<std::mutex> lk(dma_mtx_);
        if (!tx_running_ && (sadtcs_ & kTden))
            TryStartNextLocked(lk);
    }
}

void Sa1111Sac::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(dma_mtx_);
    w.Write("accar", accar_);  w.Write("accdr", accdr_);  w.Write("acsar", acsar_);
    w.Write("sadtcs", sadtcs_); w.Write("sadtsa", sadtsa_); w.Write("sadtca", sadtca_); w.Write("sadtsb", sadtsb_); w.Write("sadtcb", sadtcb_);
    w.Write("sadrcs", sadrcs_); w.Write("sadrsa", sadrsa_); w.Write("sadrca", sadrca_); w.Write("sadrsb", sadrsb_); w.Write("sadrcb", sadrcb_);
    w.Write("saitr", saitr_);
    w.Write("sacr0", sacr0_); w.Write("sacr1", sacr1_); w.Write("sacr2", sacr2_);
    w.Write("l3car", l3car_);
    w.WriteBytes("l3_regs", l3_regs_, sizeof(l3_regs_));
    w.Write<uint8_t>("l3wd", l3wd_ ? 1u : 0u);
    w.Write<uint8_t>("l3rd", l3rd_ ? 1u : 0u);
}

void Sa1111Sac::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(dma_mtx_);
    r.Read("accar", accar_);  r.Read("accdr", accdr_);  r.Read("acsar", acsar_);
    r.Read("sadtcs", sadtcs_); r.Read("sadtsa", sadtsa_); r.Read("sadtca", sadtca_); r.Read("sadtsb", sadtsb_); r.Read("sadtcb", sadtcb_);
    r.Read("sadrcs", sadrcs_); r.Read("sadrsa", sadrsa_); r.Read("sadrca", sadrca_); r.Read("sadrsb", sadrsb_); r.Read("sadrcb", sadrcb_);
    r.Read("saitr", saitr_);
    r.Read("sacr0", sacr0_); r.Read("sacr1", sacr1_); r.Read("sacr2", sacr2_);
    r.Read("l3car", l3car_);
    r.ReadBytes("l3_regs", l3_regs_, sizeof(l3_regs_));
    uint8_t l3wd = 0, l3rd = 0; r.Read("l3wd", l3wd); r.Read("l3rd", l3rd);
    l3wd_ = (l3wd != 0); l3rd_ = (l3rd != 0);
    /* No host audio sink owns a buffer after a restore; clear the in-flight TX
       so the guest re-arms on the next DMA program (mirrors Sa11xxDma). */
    tx_running_  = false;
    tx_buffer_b_ = false;
}

REGISTER_SERVICE(Sa1111Sac);
