#pragma once

#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/service.h>

#include <QSize>
#include <QTimer>
#include <Qt>

#include <vector>

class DesktopGuestFollow : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    class Request {
    public:
        explicit Request(DesktopGuestFollow& follow) : follow_(follow) { ++follow_.requests_; }
        ~Request() { --follow_.requests_; }
        Request(const Request&)            = delete;
        Request& operator=(const Request&) = delete;

    private:
        DesktopGuestFollow& follow_;
    };

    void OnReady() override;

    bool FollowsGuest() const { return follow_guest_; }
    bool InRequest() const { return requests_ > 0; }
    void Follow() { follow_guest_ = true; }
    void Placed() { placed_ = true; }
    void ExpectResize(const QSize& before, const QSize& after);
    void ExpectStates(Qt::WindowStates states);
    bool LiveResizeOn() const;
    void ArmLiveResize();
    void OnStateChange(Qt::WindowStates before, Qt::WindowStates now);
    void OnResized(const QSize& size);

private:
    void OnUserResized();
    void FireLiveResize();

    const cerfcore::InstanceGate  gate_{emu_};
    QTimer                        resize_debounce_;
    std::vector<QSize>            pending_;
    std::vector<Qt::WindowStates> pending_states_;
    int                           requests_     = 0;
    bool                          follow_guest_ = true;
    bool                          placed_       = false;
};
