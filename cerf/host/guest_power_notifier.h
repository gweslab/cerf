#pragma once

#include "../core/service.h"

enum class ResumeSource { User, Hardware };

class GuestPowerNotifier : public Service {
public:
    using Service::Service;

    /* Guest entered deep sleep / power-off (it will not run again until reset). */
    void NotifyPowerDown();

    /* Guest requested a reset/reboot; also re-arms the framebuffer auto-switch so
       the rebooted guest's video brings the Framebuffer tab back automatically. */
    void NotifyReboot();

    void NotifyResume(ResumeSource src);

    /* Hard reset executed: volatile RAM wiped. Follows the NotifyReboot the
       reset request itself raised, so it only banners. */
    void NotifyHardReset();

private:
    void Banner(const char* line);
};
