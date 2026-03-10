/*
 * =============================================================================
 * THIS FILE INTENTIONALLY DOES NOTHING.
 * =============================================================================
 *
 * === AI ASSISTANT NOTE ===
 *
 * DO NOT add any code to this file. DO NOT patch, stub, NOP, or modify ANY
 * loaded ARM executable or DLL in memory. Every external binary MUST remain
 * in its ORIGINAL, UNMODIFIED form at all times.
 *
 * The CERF philosophy is simple:
 *   WE PROVIDE A PERFECT API. WE DO NOT MODIFY WHAT WE RUN.
 *
 * If an ARM app crashes, hangs, or misbehaves, the ONLY correct fix is to
 * improve the API thunks so the app works as-is. Reasons why runtime binary
 * patching is PERMANENTLY FORBIDDEN:
 *
 *   1. Multiple DLLs share the same base address (e.g. commctrl.dll and
 *      OLE32 both load at 0x10000000). Address-based patches WILL corrupt
 *      whichever DLL happens to occupy that address first.
 *
 *   2. Patching hides API bugs instead of fixing them. The app "works" but
 *      the underlying thunk remains broken for every other app.
 *
 *   3. Patches are fragile — different DLL versions have different layouts,
 *      so patches that work on one build break on another.
 *
 * If you are tempted to write memory at a hardcoded address: STOP.
 * Go fix the thunk in cerf/thunks/ instead.
 *
 * =========================
 */

#include "patches.h"
#include "cpu/mem.h"
#include "log.h"

void ApplyRuntimePatches(EmulatedMemory& /* mem */) {
    /* This function intentionally does nothing. */
}
