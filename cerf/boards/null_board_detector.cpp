#include "board_detector.h"

#include "../core/cerf_emulator.h"

namespace {

class NullBoardDetector : public BoardDetector {
public:
    using BoardDetector::BoardDetector;

    Board       GetBoard()  const override { return Board::Unknown; }
    SocFamily   GetSoc()    const override { return SocFamily::Unknown; }
    const char* BoardName() const override { return "Unknown / unsupported"; }
};

}  /* namespace */

REGISTER_SERVICE_AS_FALLBACK(NullBoardDetector, BoardDetector);
