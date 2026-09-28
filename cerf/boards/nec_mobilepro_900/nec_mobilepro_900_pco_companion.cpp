#include "nec_mobilepro_900_pco_companion.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../socs/pxa255/pxa255_btuart.h"
#include "../board_context.h"
#include "nec_mobilepro_900_id.h"

REGISTER_SERVICE(NecMobilePro900PcoCompanion);

bool NecMobilePro900PcoCompanion::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
}

void NecMobilePro900PcoCompanion::OnReady() {
    auto& btuart = emu_.Get<Pxa255Btuart>();
    BindUart(btuart);
    btuart.SetEndpoint(this);
    LOG(Periph, "[PCO] bound as the BTUART's serial endpoint\n");
}

void NecMobilePro900PcoCompanion::OnGuestTx(const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; ++i) OnBtuartTx(data[i]);
}

/* The guest TX byte stream is not self-framing: command opcodes interleave with
   2-byte commands' data bytes and an unframed boot init blob, so each byte is matched
   independently and a stray opcode match is harmless (pulses an auto-reset event with
   no waiter). */
void NecMobilePro900PcoCompanion::OnBtuartTx(uint8_t b) {
    switch (b) {
    case 0x70u:   /* main-battery request (sub_1BC1E3C). */
        SendBatteryReply(main_battery_raw_.load(std::memory_order_acquire));
        break;
    case 0x71u:   /* backup-battery request. sub_1BC28B4 has no 0x71 case -> the reply
                     ID is 0x70 (request byte only selects the cell). No separate backup
                     source; report it as healthy as main (cosmetic - answering clears
                     the freeze). */
        SendBatteryReply(main_battery_raw_.load(std::memory_order_acquire));
        break;
    case 0x13u: {  /* keyboard scan request (sub_1BC1C00). sub_1BC1C54 accumulates 13
                      bytes then signals the scan event; no trailing 0x12 (that is the
                      async key-down notify, not part of a scan reply). */
        std::lock_guard<std::mutex> lk(report_mtx_);
        PushByte(0x13u);
        for (int i = 0; i < 13; ++i) PushByte(cur_matrix_[i]);
        break;
    }
    default:
        break;
    }
}

/* PIC_BATTERY_STATE: [0x70][hi][lo]; pco.dll sub_1BC28B4 (states 2->3) reassembles
   (hi<<8)|lo and hands it to sub_1BC1E80, which caches it and signals the wait event. */
void NecMobilePro900PcoCompanion::SendBatteryReply(uint16_t raw) {
    std::lock_guard<std::mutex> lk(report_mtx_);
    PushByte(0x70u);
    PushByte(static_cast<uint8_t>(raw >> 8));
    PushByte(static_cast<uint8_t>(raw & 0xFFu));
}

void NecMobilePro900PcoCompanion::PushByte(uint8_t b) {
    uart_->PushRx(&b, 1);
}

/* Cache only; never push to BTUART. The PICO keyboard is request/reply (Linux
   pic-pxa2xx.c): keybddr's on-demand 0x13 is answered from cur_matrix_ in
   OnBtuartTx. Pushing the matrix unsolicited floods the pco IST and re-creates the
   input freeze. */
void NecMobilePro900PcoCompanion::SetKeyMatrix(const uint8_t matrix[13]) {
    std::lock_guard<std::mutex> lk(report_mtx_);
    for (int i = 0; i < 13; ++i) cur_matrix_[i] = matrix[i];
}

uint8_t NecMobilePro900PcoCompanion::KeyMatrixByte(size_t i) {
    std::lock_guard<std::mutex> lk(report_mtx_);
    return cur_matrix_[i];
}

/* report_mtx_ keeps a report's bytes contiguous in the shared BTUART RX FIFO so
   pco's byte-stream parser (sub_1BC28B4) never sees a touch report spliced into a
   keyboard one. A lone 0x12 (PIC_KEY_DOWN) is the async key-down notify. */
void NecMobilePro900PcoCompanion::NotifyKeyDown() {
    std::lock_guard<std::mutex> lk(report_mtx_);
    PushByte(0x12u);
}

void NecMobilePro900PcoCompanion::SendTouch(uint16_t x, uint16_t y) {
    std::lock_guard<std::mutex> lk(report_mtx_);
    PushByte(0x04u);
    PushByte(static_cast<uint8_t>(x >> 8)); PushByte(static_cast<uint8_t>(x));
    PushByte(static_cast<uint8_t>(y >> 8)); PushByte(static_cast<uint8_t>(y));
}

void NecMobilePro900PcoCompanion::SendPenUp() {
    std::lock_guard<std::mutex> lk(report_mtx_);
    PushByte(0x05u);
}
