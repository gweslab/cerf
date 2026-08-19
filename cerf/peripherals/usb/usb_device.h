#pragma once

#include <cstdint>
#include <vector>

class StateWriter;
class StateReader;

class UsbDevice {
public:
    virtual ~UsbDevice() = default;

    /* USB 2.0 Spec Table 9-2 (p248): Format of Setup Data, 8 bytes. */
    struct SetupPacket {
        uint8_t  bmRequestType;
        uint8_t  bRequest;
        uint16_t wValue;
        uint16_t wIndex;
        uint16_t wLength;
    };

    /* USB 2.0 Spec Table 9-2 (p248): bmRequestType bit layout. */
    static constexpr uint8_t kReqDirDeviceToHost = 0x80u;  /* D7 */
    static constexpr uint8_t kReqTypeMask        = 0x60u;  /* D6..5 */
    static constexpr uint8_t kReqTypeStandard    = 0x00u;
    static constexpr uint8_t kReqTypeClass       = 0x20u;
    static constexpr uint8_t kReqRecipMask       = 0x1Fu;  /* D4..0 */
    static constexpr uint8_t kReqRecipDevice     = 0x00u;
    static constexpr uint8_t kReqRecipInterface  = 0x01u;
    static constexpr uint8_t kReqRecipEndpoint   = 0x02u;

    /* USB 2.0 Spec Table 9-4 (p251): Standard Request Codes. */
    static constexpr uint8_t kReqGetStatus        = 0u;
    static constexpr uint8_t kReqClearFeature     = 1u;
    static constexpr uint8_t kReqSetFeature       = 3u;
    static constexpr uint8_t kReqSetAddress       = 5u;
    static constexpr uint8_t kReqGetDescriptor    = 6u;
    static constexpr uint8_t kReqGetConfiguration = 8u;
    static constexpr uint8_t kReqSetConfiguration = 9u;
    static constexpr uint8_t kReqGetInterface     = 10u;
    static constexpr uint8_t kReqSetInterface     = 11u;

    /* USB 2.0 Spec Table 9-5 (p251): Descriptor Types. */
    static constexpr uint8_t kDescDevice        = 1u;
    static constexpr uint8_t kDescConfiguration = 2u;
    static constexpr uint8_t kDescString        = 3u;

    /* USB 2.0 Spec Table 9-6 (p252): Standard Feature Selectors. */
    static constexpr uint16_t kFeatureEndpointHalt = 0u;

    bool HandleSetup(const SetupPacket& setup, std::vector<uint8_t>& data_stage);

    /* kDescConfiguration returns the full concatenated
       configuration+interface+endpoint blob (USB 2.0 Spec 9.6.3, p264). */
    virtual bool GetDescriptor(uint8_t type, uint8_t index, uint16_t lang_id,
                               std::vector<uint8_t>& out) = 0;

    virtual bool HandleClassRequest(const SetupPacket& setup,
                                    std::vector<uint8_t>& data_stage) {
        (void)setup; (void)data_stage;
        return false;
    }

    virtual void OnBulkOut(uint8_t ep, const uint8_t* data, uint32_t len) {
        (void)ep; (void)data; (void)len;
    }

    virtual uint32_t OnBulkIn(uint8_t ep, uint8_t* dst, uint32_t max) {
        (void)ep; (void)dst; (void)max;
        return 0u;
    }

    virtual void SaveState(StateWriter&) {}
    virtual void RestoreState(StateReader&) {}
    virtual void PostRestore() {}

    uint8_t Address()             const { return address_; }
    uint8_t ConfigurationValue()  const { return configuration_; }
    bool    IsEndpointStalled(uint8_t ep) const {
        return ep < kMaxEndpoints && stalled_[ep];
    }

    /* USB 2.0 Spec 9.1.2 (p242) step 4: after a port reset, "the USB device
       is now in the Default state... All of its registers and state have
       been reset and it answers to the default address." */
    void ResetToDefault() {
        address_ = 0u;
        configuration_ = 0u;
        for (bool& s : stalled_) s = false;
    }

    virtual UsbDevice* FindByAddress(uint8_t addr) {
        return address_ == addr ? this : nullptr;
    }

protected:
    void SetEndpointStalled(uint8_t ep, bool stalled) {
        if (ep < kMaxEndpoints) stalled_[ep] = stalled;
    }

    virtual uint8_t ConfigurationCount() const { return 1u; }

    uint8_t address_       = 0u;
    uint8_t configuration_ = 0u;

private:
    static constexpr uint8_t kMaxEndpoints = 16u;
    bool stalled_[kMaxEndpoints] = {};
};
