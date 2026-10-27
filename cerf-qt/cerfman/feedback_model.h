#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

class FeedbackModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString title READ Title CONSTANT)
    Q_PROPERTY(QString header READ Header CONSTANT)
    Q_PROPERTY(QString createText READ CreateText CONSTANT)
    Q_PROPERTY(QString createUrl READ CreateUrl CONSTANT)
    Q_PROPERTY(QString loadingText READ LoadingText CONSTANT)

public:
    explicit FeedbackModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static FeedbackModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<FeedbackModel>(qml);
    }

    QString Title() const { return QStringLiteral("Feedback"); }
    QString Header() const;
    QString CreateText() const { return QStringLiteral("Create issue"); }
    QString CreateUrl() const;
    QString LoadingText() const;

    Q_INVOKABLE void Load();

signals:
    void loaded(const QVariantList& issues, const QString& note);

private:
    void Parse(const QByteArray& body);
};
