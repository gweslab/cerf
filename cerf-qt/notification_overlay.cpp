#include "notification_overlay.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(NotificationOverlay);

namespace {

const QList<QByteArray> kRoles = {"cardId", "tone", "title", "body"};

const char* Tone(const cerfcore::NotificationKind kind) {
    switch (kind) {
        case cerfcore::NotificationKind::Error:   return "error";
        case cerfcore::NotificationKind::Success: return "success";
        case cerfcore::NotificationKind::Warning: return "warning";
    }
    return "warning";
}

}

QList<QByteArray> NotificationOverlay::Roles() { return kRoles; }

const QList<QVariantMap>& NotificationOverlay::Cards() {
    auto& stack = emu_.Get<cerfcore::NotificationStack>();
    if (stack.Generation() == gen_) return rows_;
    gen_ = stack.Snapshot(cards_);
    rows_.clear();
    for (const cerfcore::NotificationCard& card : cards_) {
        const QString text = QString::fromStdString(card.text);
        const qsizetype nl = text.indexOf(QLatin1Char('\n'));
        rows_.append({{QStringLiteral("cardId"), card.id},
                      {QStringLiteral("tone"), QString::fromLatin1(Tone(card.kind))},
                      {QStringLiteral("title"), nl < 0 ? text : text.left(nl)},
                      {QStringLiteral("body"), nl < 0 ? QString() : text.mid(nl + 1)}});
    }
    return rows_;
}

void NotificationOverlay::SetPlaced(std::vector<PlacedCard> placed, QPointF scale) {
    placed_ = std::move(placed);
    scale_  = scale;
}

bool NotificationOverlay::HitTest(int x, int y, uint32_t& id) const {
    const QPointF at(x / scale_.x(), y / scale_.y());
    for (const PlacedCard& card : placed_) {
        if (!card.rect.contains(at)) continue;
        id = card.id;
        return true;
    }
    return false;
}

}
