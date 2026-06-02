#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

namespace {

class TraceCe7UsbEhciBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(0xEFD3C974u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send pre-CMN this=0x%08X "
                           "m_hUDriver=0x%08X code(R8)=0x%08X\n",
                    c.regs[5], c.regs[0], c.regs[8]);
            });
            tm.OnPc(0xEFD3C97Cu, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send branch=NOT-1 "
                           "(DeviceIoControl path) m_hUDriver=0x%08X\n",
                    c.regs[0]);
            });
            tm.OnPc(0xEFD3C9A8u, [](const TraceContext& c) {
                /* When code==0x01090030 (CFileFolder generic forward),
                   R2 points to fnIoCtlPara whose offset 4 holds the
                   underlying user IOCtl. Dump first 0x28 bytes so the
                   payload code + buffers are captured. */
                LOG(Trace, "[bisect] CRefl.Send -> BL DeviceIoControl_0 "
                           "R1(code)=0x%08X R2(in)=0x%08X R3(inSz)=0x%08X\n",
                    c.regs[1], c.regs[2], c.regs[3]);
                if (c.regs[1] == 0x01090030u) {
                    uint32_t w[10] = {};
                    for (int i = 0; i < 10; ++i) {
                        auto v = c.ReadVa32(c.regs[2] + i * 4);
                        w[i] = v.value_or(0xDEADBEEFu);
                    }
                    LOG(Trace, "[bisect]   fnIoCtlPara{ pid=0x%08X user_code=0x%08X "
                               "dwContent=0x%08X hIoRef=0x%08X lpIn=0x%08X "
                               "nInSz=0x%08X lpOut=0x%08X nOutSz=0x%08X "
                               "fUseBR=0x%08X BR=0x%08X }\n",
                        w[0], w[1], w[2], w[3], w[4], w[5],
                        w[6], w[7], w[8], w[9]);
                }
            });
            tm.OnPc(0xEFD3C9ACu, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send <- DeviceIoControl_0 "
                           "R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPc(0xEFD3C9B0u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send branch==-1 "
                           "(UDP::SendIoControl path) this=0x%08X\n",
                    c.regs[5]);
            });
            tm.OnPc(0xEFD3C9D8u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send -> BL UDP.Send R0(udp)=0x%08X "
                           "R1(code)=0x%08X R2(in)=0x%08X R3(inSz)=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
            });
            tm.OnPc(0xEFD3C9DCu, [](const TraceContext& c) {
                LOG(Trace, "[bisect] CRefl.Send convergence R0=0x%08X\n",
                    c.regs[0]);
            });

            tm.OnPc(0xEFD35B10u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] UDP.Send entry this=0x%08X "
                           "code(R1)=0x%08X\n", c.regs[0], c.regs[1]);
            });
            tm.OnPc(0xEFD35B1Cu, [](const TraceContext& c) {
                LOG(Trace, "[bisect] UDP.Send pre-CMN hDevice=0x%08X\n",
                    c.regs[0]);
            });
            tm.OnPc(0xEFD35B44u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] UDP.Send -> BL DeviceIoControl_0 "
                           "hDev=R0=0x%08X R1(code)=0x%08X\n",
                    c.regs[0], c.regs[1]);
            });
            tm.OnPc(0xEFD35B48u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] UDP.Send <- DeviceIoControl_0 "
                           "R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPc(0xEFD35B50u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] UDP.Send FAIL hDevice==-1 "
                           "this=0x%08X\n", c.regs[0]);
                (void)c;
            });

            tm.OnPc(0xEFF6F0F0u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] xxx_DeviceIoControl entry "
                           "hDev=0x%08X code=0x%08X in=0x%08X inSz=0x%08X "
                           "LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEFD36708u, [](const TraceContext& c) {
                LOG(Trace, "[bisect] DM_REL_UDriverProcIoControl +4 "
                           "R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
            });

            tm.OnRunLoopIter([fired = false](const TraceContext& c) mutable {
                if (fired) return;
                const uint32_t pc = c.pc;
                if ((pc & 0xFFFF0000u) != 0xF1010000u &&
                    (pc & 0xFFFF0000u) != 0xF1020000u) return;
                fired = true;
                LOG(Trace, "[bisect-sentinel] FIRST F101**** entry pc=0x%08X "
                           "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                           "R4=0x%08X R5=0x%08X R6=0x%08X R7=0x%08X "
                           "R8=0x%08X R9=0x%08X R10=0x%08X R11=0x%08X "
                           "R12=0x%08X LR=0x%08X SP=0x%08X CPSR=0x%08X\n",
                    pc, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[4], c.regs[5], c.regs[6], c.regs[7],
                    c.regs[8], c.regs[9], c.regs[10], c.regs[11],
                    c.regs[12], c.regs[14], c.regs[13], c.cpsr);
                for (uint32_t i = 0; i < 16; ++i) {
                    const uint32_t a = c.regs[13] + i * 4u;
                    auto v = c.ReadVa32(a);
                    LOG(Trace, "[bisect-sentinel]   stk[%2u] 0x%08X = 0x%08X\n",
                        i, a, v.value_or(0xDEADBEEFu));
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7UsbEhciBisect);

}  /* namespace */
