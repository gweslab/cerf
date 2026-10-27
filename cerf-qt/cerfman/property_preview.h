#pragma once

#include <cerfcore/core/service.h>

#include <QVariantList>

class PropertySheet;

class PropertyPreview : public cerfcore::Service {
public:
    explicit PropertyPreview(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}

    QVariantList Blocks(const PropertySheet& sheet) const;

private:
    QVariantList BoardRows(const PropertySheet& sheet) const;
    QVariantList GuestAdditionsRows(const PropertySheet& sheet) const;
    QVariantList DisplayRows(const PropertySheet& sheet) const;
    QVariantList CpuRows(const PropertySheet& sheet) const;
    QVariantList EmulatorRows(const PropertySheet& sheet) const;
};
