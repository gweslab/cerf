#pragma once

#include "../../core/service.h"

#include <cstdint>

class UsbDeviceHost;

class Imx51UsbDeviceTransfers : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void           SetHost(UsbDeviceHost* host) { host_ = host; }
    UsbDeviceHost* Host() const { return host_; }

    bool     WriteSetup(uint32_t dqh_base, const uint8_t setup[8]);
    uint32_t ExecutePrime(uint32_t dqh_base, uint32_t prime_bits);

private:
    bool ExecuteEndpoint(uint32_t dqh_base, uint32_t ep, bool dir_in);
    void TransferDtdBuffers(const uint32_t pages[5], uint8_t* host, uint32_t n, bool to_host);

    UsbDeviceHost* host_ = nullptr;
};
