#include "ford_sync2_bt_hci.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "ford_sync_2_id.h"
#include "../../socs/imx51/imx51_uart1.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint8_t kH4Event        = 0x04u;  /* H4 event packet type indicator */
constexpr uint8_t kEvtCmdComplete = 0x0Eu;  /* Command Complete event code     */
constexpr uint8_t kStatusSuccess  = 0x00u;

constexpr uint16_t kOpReset           = 0x0C03u;  /* HCI_Reset                  */
constexpr uint16_t kOpReadBdAddr      = 0x1009u;  /* HCI_Read_BD_ADDR           */
constexpr uint16_t kOpWriteBdAddr     = 0xFC01u;  /* BCM HCI_Write_BD_ADDR      */
constexpr uint16_t kOpDownloadMinidrv = 0xFC2Eu;  /* BCM HCI_DOWNLOAD_MINIDRIVER*/
constexpr uint16_t kOpWriteRam        = 0xFC4Cu;  /* BCM Vendor VS_WriteRAM     */
constexpr uint16_t kOpLaunchRam       = 0xFC4Eu;  /* BCM Vendor VS_LaunchRAM    */

/* btd init probe set (SendInitCommands sub_C06A3238); each CC must satisfy btd's
   matcher sub_C06A3E74 (status+length) or the init stalls (BTAVSVC waits on
   BthGetHardwareStatus==2). */
constexpr uint16_t kOpInquiryCancel     = 0x0402u;  /* HCI_Inquiry_Cancel       */
constexpr uint16_t kOpReadBufferSize    = 0x1005u;  /* HCI_Read_Buffer_Size     */
constexpr uint16_t kOpReadPageTimeout   = 0x0C17u;  /* HCI_Read_Page_Timeout    */
constexpr uint16_t kOpReadLocalFeatures = 0x1003u;  /* HCI_Read_Local_Features  */

/* Inquiry_Cancel with no inquiry = Command Disallowed (BlueZ btdev.c
   cmd_inquiry_cancel); btd matcher case 1026 completes only on status!=0 during
   init, so 0x00 would stall. */
constexpr uint8_t kStatusCommandDisallowed = 0x0Cu;

/* BR/EDR 2.1 controller buffer config (BlueZ btdev.c btdev_init_param):
   ACL_len(2) SCO_len(1) Num_ACL(2) Num_SCO(2). */
constexpr uint8_t kReadBufferSizeParams[7] = {
    0xC0u, 0x00u, 0x48u, 0x01u, 0x00u, 0x01u, 0x00u};

/* BR/EDR 2.1 LMP feature mask (BlueZ btdev.c set_bredr_features; BCM4325 = 2.1+EDR, no LE). */
constexpr uint8_t kReadLocalFeatures[8] = {
    0xA4u, 0x08u, 0x00u, 0xC0u, 0x18u, 0x1Eu, 0x79u, 0x83u};

/* Read_Page_Timeout power-on default (BT Core Spec Vol 4 Part E). */
constexpr uint16_t kDefaultPageTimeout = 0x2000u;

}  // namespace

bool FordSync2BtHci::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::FordSync2;
}

void FordSync2BtHci::OnReady() {
    uart_ = &emu_.Get<Imx51Uart1>();
    uart_->AttachEndpoint(this);
    LOG(Board, "[BT] endpoint attached to UART1 (COM1) @0x73FBC000\n");
}

void FordSync2BtHci::OnGuestTx(uint8_t byte) {
    if (n_ == 0) {
        if (byte != 0x01u) return;   /* resync to the H4 command type byte */
        cmd_[0] = byte;
        n_ = 1;
        return;
    }
    cmd_[n_++] = byte;
    if (n_ < 4u) return;                          /* need op_lo op_hi plen   */
    if (n_ < 4u + cmd_[3]) return;                /* + plen parameter bytes  */
    Reply();
    n_ = 0;
}

void FordSync2BtHci::Reply() {
    const uint8_t  op_lo  = cmd_[1];
    const uint8_t  op_hi  = cmd_[2];
    const uint16_t opcode = cerf::le::U16(cmd_, 1);
    /* The driver's read paths require the H4 event type 0x04 then the Command
       Complete event: sub_C07773F4 reads N bytes, asserts the leading 0x04 and
       strips it; sub_C0777478 (Read_BD_ADDR) reads it raw. So every reply leads
       with 04 0E. */
    if (opcode == kOpReadBdAddr) {
        uint8_t ev[13] = {kH4Event, kEvtCmdComplete, 0x0Au, 0x01u,
                          op_lo, op_hi, kStatusSuccess};
        for (int i = 0; i < 6; ++i) ev[7 + i] = bd_addr_[i];
        uart_->InjectRx(ev, sizeof(ev));
        LOG(Board, "[BT] Read_BD_ADDR -> Command Complete\n");
        return;
    }

    if (opcode == kOpInquiryCancel) {
        const uint8_t ev[7] = {kH4Event, kEvtCmdComplete, 0x04u, 0x01u,
                               op_lo, op_hi, kStatusCommandDisallowed};
        uart_->InjectRx(ev, sizeof(ev));
        LOG(Board, "[BT] Inquiry_Cancel -> CC status=0x0C (Command Disallowed)\n");
        return;
    }
    if (opcode == kOpReadBufferSize) {
        uint8_t ev[14] = {kH4Event, kEvtCmdComplete, 0x0Bu, 0x01u,
                          op_lo, op_hi, kStatusSuccess};
        for (int i = 0; i < 7; ++i) ev[7 + i] = kReadBufferSizeParams[i];
        uart_->InjectRx(ev, sizeof(ev));
        LOG(Board, "[BT] Read_Buffer_Size -> CC (ACL 192 x1, SCO 72 x1)\n");
        return;
    }
    if (opcode == kOpReadPageTimeout) {
        uint8_t ev[9] = {kH4Event, kEvtCmdComplete, 0x06u, 0x01u,
                         op_lo, op_hi, kStatusSuccess};
        cerf::le::Put16(ev + 7, kDefaultPageTimeout);
        uart_->InjectRx(ev, sizeof(ev));
        LOG(Board, "[BT] Read_Page_Timeout -> CC (0x2000)\n");
        return;
    }
    if (opcode == kOpReadLocalFeatures) {
        uint8_t ev[15] = {kH4Event, kEvtCmdComplete, 0x0Cu, 0x01u,
                          op_lo, op_hi, kStatusSuccess};
        for (int i = 0; i < 8; ++i) ev[7 + i] = kReadLocalFeatures[i];
        uart_->InjectRx(ev, sizeof(ev));
        LOG(Board, "[BT] Read_Local_Features -> CC (BR/EDR 2.1 mask)\n");
        return;
    }

    const uint8_t ev[7] = {kH4Event, kEvtCmdComplete, 0x04u, 0x01u,
                           op_lo, op_hi, kStatusSuccess};
    uart_->InjectRx(ev, sizeof(ev));

    if (opcode == kOpDownloadMinidrv) {
        /* sub_C0776880 reads a 2-byte launch announcement after the minidriver
           Command Complete; it only rejects ASCII "14" (0x31,0x34) and discards
           the bytes, so 00 00 satisfies it. */
        const uint8_t announce[2] = {0x00u, 0x00u};
        uart_->InjectRx(announce, sizeof(announce));
        LOG(Board, "[BT] HCI_DOWNLOAD_MINIDRIVER -> CC + launch announcement\n");
    } else if (opcode == kOpReset) {
        LOG(Board, "[BT] HCI_RESET -> Command Complete\n");
    } else if (opcode == kOpWriteBdAddr) {
        /* BTPostLoad programs a BD_ADDR then reads it back and requires the
           read-back to DIFFER from the pre-write address (sub_C07766E0 memcmp);
           store what the guest wrote so the next Read_BD_ADDR returns it. */
        if (cmd_[3] >= 6u)
            for (int i = 0; i < 6; ++i) bd_addr_[i] = cmd_[4u + i];
        LOG(Board, "[BT] Write_BD_ADDR -> CC (address stored)\n");
    } else if (opcode == kOpWriteRam || opcode == kOpLaunchRam) {
        if ((++patchram_cmds_ % 64u) == 1u)
            LOG(Board, "[BT] patchram cmd #%u (op 0x%04X) -> CC\n",
                patchram_cmds_, opcode);
    }
}

void FordSync2BtHci::SaveState(StateWriter& w) {
    w.Write<uint32_t>(n_);
    w.WriteBytes(cmd_, sizeof(cmd_));
    w.WriteBytes(bd_addr_, sizeof(bd_addr_));
}

void FordSync2BtHci::RestoreState(StateReader& r) {
    r.Read(n_);
    r.ReadBytes(cmd_, sizeof(cmd_));
    r.ReadBytes(bd_addr_, sizeof(bd_addr_));
}

REGISTER_SERVICE(FordSync2BtHci);
