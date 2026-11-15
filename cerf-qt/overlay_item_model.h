#pragma once

#include <QAbstractListModel>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class OverlayItemModel : public QAbstractListModel {
    Q_OBJECT
    QML_ANONYMOUS

public:
    explicit OverlayItemModel(QList<QByteArray> roles, QObject* parent = nullptr);

    int                    rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant               data(const QModelIndex& index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    void Update(QList<QVariantMap> rows);

private:
    bool SameKinds(const QList<QVariantMap>& rows) const;

    QList<QByteArray>  roles_;
    QList<QVariantMap> rows_;
};
