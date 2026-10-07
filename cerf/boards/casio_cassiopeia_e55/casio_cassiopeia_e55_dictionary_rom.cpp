#include "../../peripherals/casio_dictionary_rom/casio_dictionary_rom.h"

#include "../../core/cerf_emulator.h"
#include "casio_cassiopeia_e55_id.h"

#include <string_view>

namespace {

class CasioCassiopeiaE55DictionaryRom : public CasioDictionaryRomWindow {
public:
    using CasioDictionaryRomWindow::CasioDictionaryRomWindow;

protected:
    std::string_view WindowBoardId() const override { return BoardId::CasioCassiopeiaE55; }
    const char*      WindowTag()     const override { return "E55 dictionary ROM"; }
};

}

REGISTER_SERVICE(CasioCassiopeiaE55DictionaryRom);
