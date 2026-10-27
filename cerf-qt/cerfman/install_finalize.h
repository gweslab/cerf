#pragma once

#include "install_options.h"
#include "install_retry_gate.h"

#include <QString>

void FinalizeInstall(const QString& install_dir, const QString& frontend_path, const InstallOptions& options,
                     const InstallRetryGate& gate);
