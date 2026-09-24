#pragma once

#include "../../core/service.h"

#include <cstdint>

class Msm8255AdmCommandList : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    bool IsModeledCmdPtr(uint32_t value) const;
    void RequireModeledCmdPtr(uint32_t value);
    uint32_t FirstCrci(uint32_t value);
    void Run(uint32_t value, uint32_t crci);

private:
    uint32_t BusRead(uint32_t pa);
    uint32_t ReadPointerEntry(uint32_t list);
    uint32_t CrciOf(uint32_t cmd);
    void Move(uint32_t src, uint32_t dst, uint32_t len, uint32_t crci);
    void MoveBox(uint32_t src, uint32_t dst, uint32_t len_word,
                 uint32_t rows_word, uint32_t off_word, uint32_t pa,
                 uint32_t crci);
    void RunCommandArray(uint32_t pa, uint32_t crci);
};
