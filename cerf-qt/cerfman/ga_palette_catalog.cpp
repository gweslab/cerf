#include "ga_palette_catalog.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/ga_palette_json.h>

#include <QColor>

#include <optional>
#include <vector>

REGISTER_SERVICE(GaPaletteCatalog);

QVariantList GaPaletteCatalog::Choices(uint32_t bpp) const {
    QVariantList out;
    for (const cerfcore::DbGaPalette& palette : emu_.Get<cerfcore::BoardDatabase>().GaPalettes())
        if (palette.bpp == bpp) out.append(QString::fromStdString(palette.id));
    if (!out.isEmpty()) out.prepend(NullVariant());
    return out;
}

QVariant GaPaletteCatalog::ChoiceOf(const Json& colors) const {
    const std::optional<std::vector<uint32_t>> parsed = cerfcore::GaPaletteFromJson(colors);
    if (parsed)
        for (const cerfcore::DbGaPalette& palette : emu_.Get<cerfcore::BoardDatabase>().GaPalettes())
            if (palette.colors == *parsed) return QString::fromStdString(palette.id);
    return QString::fromLatin1(kCustomChoice);
}

QString GaPaletteCatalog::Label(const QVariant& choice, uint32_t bpp) const {
    auto& db = emu_.Get<cerfcore::BoardDatabase>();
    if (choice.isNull()) {
        const cerfcore::DbGaPalette* fallback = db.DefaultGaPalette(bpp);
        return fallback ? QStringLiteral("Auto - %1").arg(QString::fromStdString(fallback->name)) : QString();
    }
    const std::string id = choice.toString().toStdString();
    for (const cerfcore::DbGaPalette& palette : db.GaPalettes())
        if (palette.id == id) return QString::fromStdString(palette.name);
    return QStringLiteral("Custom");
}

Json GaPaletteCatalog::ColorsOf(const QString& id) const {
    const std::string wanted = id.toStdString();
    for (const cerfcore::DbGaPalette& palette : emu_.Get<cerfcore::BoardDatabase>().GaPalettes())
        if (palette.id == wanted) return cerfcore::GaPaletteToJson<Json>(palette.colors);
    return Json();
}

QVariantList GaPaletteCatalog::Swatches(const Json* colors, uint32_t bpp) const {
    std::vector<uint32_t> shown;
    if (colors) {
        shown = cerfcore::GaPaletteFromJson(*colors).value_or(std::vector<uint32_t>());
    } else if (const cerfcore::DbGaPalette* fallback = emu_.Get<cerfcore::BoardDatabase>().DefaultGaPalette(bpp)) {
        shown = fallback->colors;
    }
    QVariantList out;
    for (const uint32_t rgb : shown) out.append(QColor(QRgb(rgb)));
    return out;
}
