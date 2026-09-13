#pragma once

#include <cstdint>

constexpr uint32_t Iop13xxCp6Key(uint32_t crn, uint32_t crm,
                                 uint32_t opc2 = 0, uint32_t opc1 = 0) {
    return crn | (crm << 4) | (opc2 << 8) | (opc1 << 11);
}

/* Intel 81341/81342 I/O Processors Developer's Manual, sections 2.2.1,
   2.2.2 and 2.2.4. */
constexpr uint32_t kCp6ResetCause = Iop13xxCp6Key(0, 1);
constexpr uint32_t kCp6IntBase = Iop13xxCp6Key(0, 2);
constexpr uint32_t kCp6IntSize = Iop13xxCp6Key(2, 2);
constexpr uint32_t kCp6IntVec = Iop13xxCp6Key(3, 2);

constexpr uint32_t kCp6IntCtl0 = Iop13xxCp6Key(0, 4);
constexpr uint32_t kCp6IntCtl1 = Iop13xxCp6Key(1, 4);
constexpr uint32_t kCp6IntCtl2 = Iop13xxCp6Key(2, 4);
constexpr uint32_t kCp6IntCtl3 = Iop13xxCp6Key(3, 4);

constexpr uint32_t kCp6IntStr0 = Iop13xxCp6Key(0, 5);
constexpr uint32_t kCp6IntStr1 = Iop13xxCp6Key(1, 5);
constexpr uint32_t kCp6IntStr2 = Iop13xxCp6Key(2, 5);
constexpr uint32_t kCp6IntStr3 = Iop13xxCp6Key(3, 5);

constexpr uint32_t kCp6Timer0Control = Iop13xxCp6Key(0, 9);
constexpr uint32_t kCp6Timer1Control = Iop13xxCp6Key(1, 9);
constexpr uint32_t kCp6Timer0Counter = Iop13xxCp6Key(2, 9);
constexpr uint32_t kCp6Timer1Counter = Iop13xxCp6Key(3, 9);
constexpr uint32_t kCp6Timer0Reload = Iop13xxCp6Key(4, 9);
constexpr uint32_t kCp6Timer1Reload = Iop13xxCp6Key(5, 9);
constexpr uint32_t kCp6TimerStatus = Iop13xxCp6Key(6, 9);
constexpr uint32_t kCp6WatchdogCtrl = Iop13xxCp6Key(7, 9);
constexpr uint32_t kCp6WatchdogStat = Iop13xxCp6Key(8, 9);
