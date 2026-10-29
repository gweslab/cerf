#pragma once

enum class ProcessMode { kManager, kEmulator, kInstallStage };

ProcessMode DetectProcessMode(int argc, char** argv);
