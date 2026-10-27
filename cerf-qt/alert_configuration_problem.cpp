#include <cerfcore/host/configuration_problem.h>
#include <cerfcore/host/user_alert.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>

#include "executable_names_text.h"

namespace cerffrontend {

namespace {

class AlertConfigurationProblem : public cerfcore::ConfigurationProblem {
public:
    using cerfcore::ConfigurationProblem::ConfigurationProblem;

    void DeviceRomMissing(const std::string& device) override {
        emu_.Get<cerfcore::UserAlert>().Show(
            cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kStandalone,
            "Device not found - " CERF_PRODUCT_NAME,
            "Device \"" + device + "\" has no ROM on disk.\n\nOpen " CERF_PRODUCT_NAME " to install it.");
    }

    void BoardUnsupported(const std::string& board_id) override {
        const std::string msg =
            board_id.empty()
                ? std::string("No board selected.\n\nSet \"board\": { \"id\": ... } in cerf.json, or pass "
                              "--board-id=ID. CERF will exit.")
                : "Unrecognised board id '" + board_id +
                      "'.\n\nRun " CERF_FRONTEND_NAME " --help for the supported id list. CERF will exit.";
        emu_.Get<cerfcore::UserAlert>().Show(cerfcore::AlertLevel::kError,
                                             cerfcore::AlertPlacement::kStandalone,
                                             "Unsupported board - " CERF_PRODUCT_NAME, msg);
    }

    void LaunchCompactFlashMissing(const std::string& card_name) override {
        emu_.Get<cerfcore::UserAlert>().Show(
            cerfcore::AlertLevel::kWarning, cerfcore::AlertPlacement::kStandalone,
            "Missing CF Card - " CERF_PRODUCT_NAME,
            "This ROM requires additional package '" + card_name +
                "' CF card to be present in the device directory. You can do that in " CERF_PRODUCT_NAME
                ", in the side panel of the device.\n\n"
                "The guest might not boot as intended without this card attached.");
    }
};

}

REGISTER_SERVICE_AS(AlertConfigurationProblem, cerfcore::ConfigurationProblem);

}
