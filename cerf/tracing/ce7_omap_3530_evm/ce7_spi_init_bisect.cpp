#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcSpiInitEntry        = 0xEF182DF8u;
constexpr uint32_t kPcPostLocalAlloc      = 0xEF182E18u;
constexpr uint32_t kPcPostCreateMutexW    = 0xEF182E60u;
constexpr uint32_t kPcPostGetRegistry     = 0xEF182E80u;  /* R0=0 success, non-0 fail */
constexpr uint32_t kPcPostCreateBus       = 0xEF182ED4u;
constexpr uint32_t kPcPostMmMapIoSpace    = 0xEF182FB4u;
constexpr uint32_t kPcPostKernelIoControl = 0xEF182FE0u;  /* IOCTL_HAL_REQUEST_SYSINTR */
constexpr uint32_t kPcPostCreateIntrEvent = 0xEF182FFCu;
constexpr uint32_t kPcPostInterruptInit   = 0xEF183018u;
constexpr uint32_t kPcLabel29             = 0xEF1830BCu;  /* cleanup-and-fail */
constexpr uint32_t kPcSuccessReturn       = 0xEF183094u;  /* R7=R4 — keep handle */
constexpr uint32_t kPcSysconfigWrite      = 0xEF183030u;  /* STR R3, [R2,#0x10] — SYSCONFIG SOFTRESET */
constexpr uint32_t kPcSysstatusRead       = 0xEF183050u;  /* LDR R3, [R3,#0x14] — SYSSTATUS poll */
constexpr uint32_t kPcSysstatusReadResult = 0xEF183054u;  /* TST R3, #1 — R3 now holds the read value */

constexpr uint32_t kPcSpiOpen             = 0xEF18211Cu;
constexpr uint32_t kPcSpiConfigure        = 0xEF182200u;
constexpr uint32_t kPcSpiWriteRead        = 0xEF182900u;
constexpr uint32_t kPcSpiIOControl        = 0xEF183344u;

class TraceCe7SpiInitBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kPcSpiInitEntry, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] ENTRY szContext=0x%08X pBusContext=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcPostLocalAlloc, [](const TraceContext& c) {
                LOG(Trace, "[spi-init] post-LocalAlloc R0=0x%08X (NULL=fail)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostCreateMutexW, [](const TraceContext& c) {
                LOG(Trace, "[spi-init] post-CreateMutexW R0=0x%08X (NULL=fail)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostGetRegistry, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-GetDeviceRegistryParams R0=0x%08X "
                    "(0=success, non-0=fail-to-LABEL_29)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostCreateBus, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-CreateBusAccessHandle R0=0x%08X (NULL=fail)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostMmMapIoSpace, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-MmMapIoSpace R0=0x%08X (NULL=fail-to-LABEL_29)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostKernelIoControl, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-KernelIoControl(IOCTL_HAL_REQUEST_SYSINTR=0x01010098) "
                    "R0=0x%08X (0=fail-to-LABEL_29, non-0=success)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostCreateIntrEvent, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-CreateEventW(hIntrEvent) R0=0x%08X (NULL=fail)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcPostInterruptInit, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] post-InterruptInitialize R0=0x%08X "
                    "(0=fail-to-LABEL_29, non-0=success)\n",
                    c.regs[0]);
            });
            tm.OnPc(kPcLabel29, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] LABEL_29 reached — SPI_Deinit + return 0 "
                    "(R4=pDevice=0x%08X)\n",
                    c.regs[4]);
            });
            tm.OnPc(kPcSuccessReturn, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] SUCCESS R4=0x%08X — will return handle\n",
                    c.regs[4]);
            });
            tm.OnPc(kPcSysconfigWrite, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] STR SYSCONFIG: addr=0x%08X(=R2+0x10) val=0x%08X\n",
                    c.regs[2] + 0x10u, c.regs[3]);
            });
            tm.OnPc(kPcSysstatusRead, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] LDR SYSSTATUS: addr=0x%08X(=R3+0x14) R3-pre=0x%08X\n",
                    c.regs[3] + 0x14u, c.regs[3]);
            });
            tm.OnPc(kPcSysstatusReadResult, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-init] SYSSTATUS-read-result R3=0x%08X (bit0=RESETDONE; "
                    "if real McSPI=0x00000001, if RAM=unrelated value)\n",
                    c.regs[3]);
            });
            tm.OnPc(kPcSpiOpen, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-api] SPI_Open ENTRY context=0x%08X access=0x%08X share=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(kPcSpiConfigure, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-api] SPI_Configure ENTRY ctx=0x%08X slaveAddr=0x%08X config=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(kPcSpiWriteRead, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-api] SPI_WriteRead ENTRY ctx=0x%08X size=0x%08X txBuf=0x%08X rxBuf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(kPcSpiIOControl, [](const TraceContext& c) {
                LOG(Trace,
                    "[spi-api] SPI_IOControl ENTRY ctx=0x%08X code=0x%08X inBuf=0x%08X inSize=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7SpiInitBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
