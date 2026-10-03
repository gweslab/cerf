#pragma once

#include "ucb1x00_board.h"

class Ucb1x00SibBoard : public Ucb1x00Board {
public:
    using Ucb1x00Board::Ucb1x00Board;

    void OnIrqOutChanged(bool asserted) final;
};
