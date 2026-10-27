#pragma once

#include <cerfcore/core/service.h>

#include <QCursor>

#include <cstdint>

class QtGuestCursor : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    QCursor Resolve(bool& active);

private:
    QCursor  built_{Qt::BlankCursor};
    uint32_t built_generation_ = 0;
};
