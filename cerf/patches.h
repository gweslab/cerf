#pragma once

class EmulatedMemory;

/* Legacy entry point — intentionally does nothing.
   Runtime binary patching is PERMANENTLY FORBIDDEN.
   Fix API thunks instead. See patches.cpp for details. */
void ApplyRuntimePatches(EmulatedMemory& mem);
