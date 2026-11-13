#include "cerfman/property_fields.h"
#include "live_property_sheet.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/customizations_editor.h>

namespace cerffrontend {

namespace {

class LiveCustomizationsEditor : public cerfcore::CustomizationsEditor {
public:
    using cerfcore::CustomizationsEditor::CustomizationsEditor;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    bool Open(bool force_reboot) override {
        return emu_.Get<LivePropertySheet>().Open(sheet_page::kGuestAdditions, force_reboot);
    }
};

}

REGISTER_SERVICE_AS(LiveCustomizationsEditor, cerfcore::CustomizationsEditor);

}
