#pragma once

#include <cerfcore/core/service.h>

#include <QByteArray>
#include <QList>
#include <QVariantMap>

#include <atomic>

namespace cerffrontend {

class HwScreenLog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    static QList<QByteArray>  Roles();
    bool                      Rebuild();
    const QList<QVariantMap>& Lines() const { return rows_; }

private:
    QList<QVariantMap> rows_;
    std::atomic<bool>  dirty_{true};
};

}
