#include "coproc_emitter.h"

#include "../boards/board_detector.h"
#include "../core/cerf_emulator.h"

namespace {

class NullCoprocEmitter : public CoprocEmitter {
public:
    using CoprocEmitter::CoprocEmitter;

    bool ShouldRegister() override {
        return emu_.Get<BoardDetector>().GetBoard() == Board::Unknown;
    }

    uint8_t* EmitRegisterTransfer(uint8_t* cursor, DecodedInsn*,
                                  BlockContext*) override { return cursor; }
    uint8_t* EmitDataTransfer    (uint8_t* cursor, DecodedInsn*,
                                  BlockContext*) override { return cursor; }
    uint8_t* EmitDataOperation   (uint8_t* cursor, DecodedInsn*,
                                  BlockContext*) override { return cursor; }
};

}  /* namespace */

REGISTER_SERVICE_AS(NullCoprocEmitter, CoprocEmitter);
