#include "../../peripherals/casio_dictionary_rom/casio_dictionary_rom.h"

#include "../../core/cerf_emulator.h"
#include "casio_cassiopeia_em500_id.h"

#include <string_view>

namespace {

class CasioCassiopeiaEm500DictionaryRom : public CasioDictionaryRomWindow {
public:
    using CasioDictionaryRomWindow::CasioDictionaryRomWindow;

protected:
    std::string_view WindowBoardId() const override { return BoardId::CasioCassiopeiaEm500; }
    const char*      WindowTag()     const override { return "EM500 dictionary ROM"; }
};

}

REGISTER_SERVICE(CasioCassiopeiaEm500DictionaryRom);
