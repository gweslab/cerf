#pragma once

#include "json_file.h"

#include <cerfcore/core/service.h>

#include <QString>
#include <QVariant>
#include <QVariantList>

#include <cstdint>

class GaPaletteCatalog : public cerfcore::Service {
public:
    static constexpr char kCustomChoice[] = "custom";

    explicit GaPaletteCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}

    QVariantList Choices(uint32_t bpp) const;
    QVariant     ChoiceOf(const Json& colors) const;
    QString      Label(const QVariant& choice, uint32_t bpp) const;
    Json         ColorsOf(const QString& id) const;
    QVariantList Swatches(const Json* colors, uint32_t bpp) const;
};
