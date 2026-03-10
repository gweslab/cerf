#pragma once
/* Per-thread ARM execution context.
   Each ARM thread (main + spawned) gets its own ArmCpu, TLS, stack,
   callback_executor, and marshal buffers. Accessed via thread_local t_ctx. */
#include "../cpu/arm_cpu.h"
#include <cstdint>
#include <functional>
#include <atomic>

struct ThreadContext {
    ArmCpu cpu;
    uint64_t thunk_call_count = 0;
    uint32_t marshal_base = 0x3F000000;
    uint8_t kdata[0x1000] = {};  /* per-thread KData page (TLS, thread ID) */

    using CallbackExecutor = std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)>;
    CallbackExecutor callback_executor;
};

/* Current thread's context. Set at thread start, never null during ARM execution. */
extern thread_local ThreadContext* t_ctx;

/* Thread index counter for allocating per-thread resources. */
extern std::atomic<int> g_next_thread_index;

class Win32Thunks;  /* forward */
class EmulatedMemory;

/* Initialize KData page for a thread context (TLS pointer, thread ID, process ID).
   Copies shared state (TLS allocator counter) from the base KData page first. */
void InitThreadKData(ThreadContext* ctx, EmulatedMemory& mem, uint32_t thread_id);

/* Create the callback_executor lambda for a thread context.
   The executor saves/restores CPU state, runs ARM code until sentinel,
   and includes the infinite-loop watchdog. */
void MakeCallbackExecutor(ThreadContext* ctx, EmulatedMemory& mem,
                          Win32Thunks& thunks, uint32_t sentinel);
