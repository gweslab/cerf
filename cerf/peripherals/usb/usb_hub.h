#pragma once

#include "usb_device.h"
#include "usb_host_port.h"

#include <cstdint>
#include <vector>

class UsbHub : public UsbDevice, public UsbHostPortHost {
public:
    explicit UsbHub(int num_ports);

    /* USB 2.0 Spec 11.24 Table 11-16 (p421): Hub Class Request Codes. */
    static constexpr uint8_t kHubReqGetStatus     = 0u;
    static constexpr uint8_t kHubReqClearFeature  = 1u;
    static constexpr uint8_t kHubReqSetFeature    = 3u;
    static constexpr uint8_t kHubReqGetDescriptor = 6u;

    /* USB 2.0 Spec Table 11-17 (p421-422): Hub Class Feature Selectors,
       port recipient. */
    static constexpr uint16_t kFeaturePortConnection   = 0u;
    static constexpr uint16_t kFeaturePortEnable       = 1u;
    static constexpr uint16_t kFeaturePortSuspend      = 2u;
    static constexpr uint16_t kFeaturePortOverCurrent  = 3u;
    static constexpr uint16_t kFeaturePortReset        = 4u;
    static constexpr uint16_t kFeaturePortPower        = 8u;
    static constexpr uint16_t kFeatureCPortConnection  = 16u;
    static constexpr uint16_t kFeatureCPortEnable      = 17u;
    static constexpr uint16_t kFeatureCPortSuspend     = 18u;
    static constexpr uint16_t kFeatureCPortOverCurrent = 19u;
    static constexpr uint16_t kFeatureCPortReset       = 20u;

    UsbHostPort& Port(int index) { return ports_[static_cast<size_t>(index)]; }
    int          NumPorts() const { return static_cast<int>(ports_.size()); }

    bool GetDescriptor(uint8_t type, uint8_t index, uint16_t lang_id,
                       std::vector<uint8_t>& out) override;
    bool HandleClassRequest(const SetupPacket& setup,
                            std::vector<uint8_t>& data_stage) override;
    uint32_t OnBulkIn(uint8_t ep, uint8_t* dst, uint32_t max) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    void OnPortConnectChanged(int port_index) override;

    UsbDevice* FindByAddress(uint8_t addr) override;

private:
    /* USB 2.0 Spec Table 11-21 (p427): Port Status Field, wPortStatus. */
    static constexpr uint16_t kPortStatusConnection = 1u << 0;
    static constexpr uint16_t kPortStatusEnable     = 1u << 1;
    static constexpr uint16_t kPortStatusReset      = 1u << 4;
    static constexpr uint16_t kPortStatusPower      = 1u << 8;
    /* USB 2.0 Spec Table 11-22 (p431): Port Change Field, wPortChange. */
    static constexpr uint16_t kPortChangeConnection = 1u << 0;
    static constexpr uint16_t kPortChangeReset      = 1u << 4;

    std::vector<uint8_t>  BuildDeviceDescriptor() const;
    std::vector<uint8_t>  BuildConfigurationDescriptor() const;
    std::vector<uint8_t>  BuildHubDescriptor() const;

    std::vector<UsbHostPort> ports_;
    std::vector<uint16_t>    port_status_;
    std::vector<uint16_t>    port_change_;
};
