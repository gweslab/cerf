#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/user_alert.h>

#include <string>

namespace cerffrontend {

namespace {

class QtMachineFailureAlerts : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        emu_.Get<cerfcore::MachineObjectTree>().Subscribe([this](const cerfcore::MachineEvent& event) {
            if (event.kind == cerfcore::MachineEventKind::kFailed) Alert(event);
        });
    }

private:
    static std::string SerialDetail(const cerfcore::MachineEvent& event) {
        const std::string code = std::to_string(event.code);
        if (event.reason == "open_failed") return "The port could not be opened (error " + code + ").";
        if (event.reason == "read_failed") return "Reading from the port failed (error " + code + ").";
        if (event.reason == "write_failed") return "Writing to the port failed (error " + code + ").";
        return "The port stopped accepting data (write timed out).";
    }

    static bool SerialReason(const std::string& reason) {
        return reason == "open_failed" || reason == "read_failed" || reason == "write_failed" ||
               reason == "write_timeout";
    }

    void Alert(const cerfcore::MachineEvent& event) {
        auto& alert = emu_.Get<cerfcore::UserAlert>();
        if (SerialReason(event.reason)) {
            alert.Post(cerfcore::AlertLevel::kWarning, "Serial port forwarder - " CERF_PRODUCT_NAME,
                       "The serial port forwarder lost host " + event.subject + ".\n\n" + SerialDetail(event) +
                           "\n\nThe port has been ejected. Check that the port exists and is not in use by another "
                           "application, then insert it again.",
                       [] {});
            return;
        }
        if (event.reason == "image_build_failed") {
            alert.Show(cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kOverWindow,
                       "Generate CompactFlash image", "The CompactFlash image could not be written: " + event.subject);
            return;
        }
        if (event.reason == "image_open_failed") {
            alert.Show(cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kOverWindow, "Media Hub",
                       "Cannot open existing media image: " + event.subject);
            return;
        }
#if !CERF_DEV_MODE
        if (event.reason == "panic_reboot_request") {
            alert.Show(cerfcore::AlertLevel::kWarning, cerfcore::AlertPlacement::kTopmost,
                       "Sync 2 panic reboot - " CERF_PRODUCT_NAME,
                       "Sync 2 has panicked and requested a reboot over VMCU.\n\n"
                       "One possibility is a dirty/corrupted NAND image: delete " +
                           event.subject +
                           " and try flashing again.\n\n"
                           "CERF does not restart the guest, so it stays alive for debugging.");
        }
#endif
    }
};

}

REGISTER_SERVICE(QtMachineFailureAlerts);

}
