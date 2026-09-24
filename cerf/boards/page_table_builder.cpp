#include "page_table_builder.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"

#include <typeinfo>

DramRegion PageTableBuilder::EntryXipRomRegion() const {
    emu_.Get<Fatal>().Die("%s declares no entry-XIP ROM region", typeid(*this).name());
}
