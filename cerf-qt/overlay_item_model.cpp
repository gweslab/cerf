#include "overlay_item_model.h"

#include <utility>

namespace {

constexpr char kKindRole[] = "kind";

}

OverlayItemModel::OverlayItemModel(QList<QByteArray> roles, QObject* parent)
    : QAbstractListModel(parent), roles_(std::move(roles)) {}

int OverlayItemModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

QVariant OverlayItemModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size() || role < Qt::UserRole || role - Qt::UserRole >= roles_.size())
        return {};
    return rows_[index.row()].value(QString::fromLatin1(roles_[role - Qt::UserRole]));
}

QHash<int, QByteArray> OverlayItemModel::roleNames() const {
    QHash<int, QByteArray> names;
    for (qsizetype i = 0; i < roles_.size(); ++i) names.insert(Qt::UserRole + static_cast<int>(i), roles_[i]);
    return names;
}

bool OverlayItemModel::SameKinds(const QList<QVariantMap>& rows) const {
    if (rows.size() != rows_.size()) return false;
    const QString kind = QString::fromLatin1(kKindRole);
    for (qsizetype i = 0; i < rows.size(); ++i)
        if (rows[i].value(kind) != rows_[i].value(kind)) return false;
    return true;
}

void OverlayItemModel::Update(QList<QVariantMap> rows) {
    if (!SameKinds(rows)) {
        beginResetModel();
        rows_ = std::move(rows);
        endResetModel();
        return;
    }
    for (qsizetype i = 0; i < rows.size(); ++i) {
        if (rows[i] == rows_[i]) continue;
        rows_[i] = std::move(rows[i]);
        const QModelIndex at = index(static_cast<int>(i));
        emit dataChanged(at, at);
    }
}
