#include "s3c2410_iis_tx_fifo.h"

#include "../../state/state_stream.h"

void S3C2410IisTxFifo::Reset() {
    Clear();
    fifo_.fill(0u);
}

void S3C2410IisTxFifo::Clear() {
    head_  = 0u;
    count_ = 0u;
}

bool S3C2410IisTxFifo::Reserve(uint32_t entries) {
    if (count_ + reserved_ + entries > kDepth) return false;
    reserved_ += entries;
    return true;
}

void S3C2410IisTxFifo::Release(uint32_t entries) {
    reserved_ -= entries;
}

bool S3C2410IisTxFifo::Push(uint16_t sample) {
    if (count_ >= kDepth) return false;
    fifo_[(head_ + count_) % kDepth] = sample;
    ++count_;
    return true;
}

uint16_t S3C2410IisTxFifo::Pop() {
    if (count_ == 0u) return 0u;
    const uint16_t sample = fifo_[head_];
    head_ = (head_ + 1u) % kDepth;
    --count_;
    return sample;
}

void S3C2410IisTxFifo::Save(StateWriter& w) const {
    w.Write<uint32_t>("tx_count", count_);
    w.Write<uint32_t>("tx_head", head_);
    w.WriteBytes("tx_fifo", fifo_.data(), sizeof(fifo_));
}

void S3C2410IisTxFifo::Restore(StateReader& r) {
    r.Read("tx_count", count_);
    r.Read("tx_head", head_);
    r.ReadBytes("tx_fifo", fifo_.data(), sizeof(fifo_));
    if (count_ > kDepth || head_ >= kDepth)
        r.Reject("transmit FIFO count %u head %u past depth %u", count_, head_, kDepth);
}
