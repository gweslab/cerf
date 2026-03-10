#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "thread_context.h"
#include "win32_thunks.h"
#include "../log.h"

thread_local ThreadContext* t_ctx = nullptr;
thread_local uint8_t* EmulatedMemory::kdata_override = nullptr;
std::atomic<int> g_next_thread_index{0};

void InitThreadKData(ThreadContext* ctx, EmulatedMemory& mem, uint32_t thread_id) {
    memset(ctx->kdata, 0, sizeof(ctx->kdata));
    /* KData layout (mapped at 0xFFFFC000-0xFFFFCFFF):
       TLS pre-TLS DWORDs at offset 0x000 (7 words)
       TLS slot array at offset 0x01C (64 slots)
       KDataStruct at offset 0x800:
         +0x000: lpvTls -> TLS slot 0 address
         +0x004: ahSys[0] SH_WIN32
         +0x008: ahSys[1] SH_CURTHREAD
         +0x00C: ahSys[2] SH_CURPROC */
    uint32_t tls_slot0 = 0xFFFFC000 + 7 * 4;  /* 0xFFFFC01C */
    /* Write lpvTls at KData+0 (offset 0x800 in the page) */
    *(uint32_t*)(ctx->kdata + 0x800) = tls_slot0;
    *(uint32_t*)(ctx->kdata + 0x804) = thread_id;
    *(uint32_t*)(ctx->kdata + 0x808) = thread_id;
    *(uint32_t*)(ctx->kdata + 0x80C) = GetCurrentProcessId();
    LOG(EMU, "[EMU] InitThreadKData: tid=%u, lpvTls=0x%08X\n", thread_id, tls_slot0);
}

void MakeCallbackExecutor(ThreadContext* ctx, EmulatedMemory& mem,
                          Win32Thunks& thunks, uint32_t sentinel) {
    ctx->callback_executor = [ctx, &mem, &thunks, sentinel](
            uint32_t arm_addr, uint32_t* args, int nargs) -> uint32_t {
        static thread_local int cb_depth = 0;
        ArmCpu& cpu = ctx->cpu;
        cb_depth++;
        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor NESTED depth=%d addr=0x%08X "
                "args=[0x%X,0x%X,0x%X,0x%X]\n",
                cb_depth, arm_addr,
                nargs > 0 ? args[0] : 0, nargs > 1 ? args[1] : 0,
                nargs > 2 ? args[2] : 0, nargs > 3 ? args[3] : 0);
        }
        /* Save CPU state */
        uint32_t saved_regs[16];
        memcpy(saved_regs, cpu.r, sizeof(saved_regs));
        uint32_t saved_cpsr = cpu.cpsr;
        bool saved_halted = cpu.halted;
        cpu.halted = false;

        /* Set up callback arguments (R0-R3) */
        for (int i = 0; i < nargs && i < 4; i++)
            cpu.r[i] = args[i];
        /* Set LR to sentinel so we know when the callback returns */
        cpu.r[REG_LR] = sentinel;
        /* Set PC to ARM function address */
        if (arm_addr & 1) {
            cpu.cpsr |= PSR_T;
            cpu.r[REG_PC] = arm_addr & ~1u;
        } else {
            cpu.cpsr &= ~PSR_T;
            cpu.r[REG_PC] = arm_addr;
        }
        /* Allocate stack frame and push extra args */
        cpu.r[REG_SP] -= 0x100;
        for (int i = 4; i < nargs; i++)
            mem.Write32(cpu.r[REG_SP] + (uint32_t)(i - 4) * 4, args[i]);

        /* Run until callback returns (hits sentinel) */
        uint32_t step_count = 0;
        uint32_t last_thunk_step = 0;
        uint64_t last_thunk_count = ctx->thunk_call_count;
        uint64_t start_thunk_count = ctx->thunk_call_count;
        while (!cpu.halted) {
            uint32_t pc = cpu.r[REG_PC];
            if (pc == sentinel || pc == (sentinel & ~1u)) break;
            if (pc < 0x1000 && cb_depth > 1) {
                LOG(API, "[API] callback_executor: NULL function pointer "
                    "(PC=0x%08X) at depth=%d, aborting\n", pc, cb_depth);
                cpu.r[0] = 0;
                break;
            }
            ++step_count;
            if (ctx->thunk_call_count != last_thunk_count) {
                last_thunk_step = step_count;
                last_thunk_count = ctx->thunk_call_count;
            }
            if (step_count - last_thunk_step > 50000000 ||
                ctx->thunk_call_count - start_thunk_count > 200000) {
                bool pure_arm = (step_count - last_thunk_step > 50000000);
                LOG(API, "\n[FATAL] callback_executor: infinite loop (%s) "
                    "at PC=0x%08X depth=%d steps=%u thunks=%llu\n",
                    pure_arm ? "pure ARM" : "thunk-calling",
                    pc, cb_depth, step_count,
                    ctx->thunk_call_count - start_thunk_count);
                LOG(API, "[FATAL] ARM state is corrupt — exiting.\n");
                LOG(API, "[FATAL] Fix the root cause before restarting.\n\n");
                Log::Close();
                ExitProcess(1);
            }
            cpu.Step();
        }
        if (cpu.halted && cb_depth > 1) {
            LOG(API, "[API] callback_executor HALTED at depth=%d "
                "PC=0x%08X R0=0x%X LR=0x%X\n",
                cb_depth, cpu.r[REG_PC], cpu.r[0], cpu.r[REG_LR]);
        }
        uint32_t result = cpu.r[0];
        /* Restore CPU state */
        memcpy(cpu.r, saved_regs, sizeof(saved_regs));
        cpu.cpsr = saved_cpsr;
        cpu.halted = saved_halted;
        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor RETURN depth=%d result=0x%X\n",
                cb_depth, result);
        }
        cb_depth--;
        return result;
    };
}
