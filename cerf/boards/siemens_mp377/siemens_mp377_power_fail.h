#pragma once

#include "../../core/service.h"
#include "../../host/host_widget.h"

#include <atomic>
#include <string>
#include <vector>

namespace siemens_mp377 {

/* siemens_mp377_v1040, PowerFail.dll: initialization 0x02951988-0x02951A24;
   IstPowerFail 0x02951670-0x02951900. */
class SiemensMp377PowerFail final : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void SetAsserted(bool asserted);

    std::wstring WidgetName() const override { return L"External power"; }
    WidgetGroup Group() const override { return WidgetGroup::Power; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    bool PrimaryActionOpensMenu() const override { return true; }
    bool PollDirty() override;

private:
    void Reset();
    void RefreshIrq();

    std::atomic<bool> asserted_{false};
    bool last_drawn_asserted_ = false;
};

} // namespace siemens_mp377
