#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>
#include "../product_links.h"

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class ProductLinksModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_NAMED_ELEMENT(ProductLinks)
    QML_SINGLETON
    Q_PROPERTY(QString productName READ ProductName CONSTANT)
    Q_PROPERTY(QString guestAdditionsUrl READ GuestAdditionsUrl CONSTANT)
    Q_PROPERTY(QString websiteUrl READ WebsiteUrl CONSTANT)
    Q_PROPERTY(QString discordUrl READ DiscordUrl CONSTANT)
    Q_PROPERTY(QString donateUrl READ DonateUrl CONSTANT)

public:
    explicit ProductLinksModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static ProductLinksModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<ProductLinksModel>(qml);
    }

    QString ProductName() const;
    QString GuestAdditionsUrl() const;
    QString WebsiteUrl() const;
    QString DiscordUrl() const;
    QString DonateUrl() const;
};
