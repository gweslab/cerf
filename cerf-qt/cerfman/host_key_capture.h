#pragma once

#include <QQuickItem>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <vector>

class HostKeyCapture : public QQuickItem {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QVariantList vks READ Vks WRITE SetVks NOTIFY changed)
    Q_PROPERTY(QVariantList resetVks READ ResetVks WRITE SetResetVks NOTIFY changed)
    Q_PROPERTY(QString label READ Label NOTIFY changed)

public:
    explicit HostKeyCapture(QQuickItem* parent = nullptr);

    QVariantList Vks() const;
    void         SetVks(const QVariantList& vks);
    QVariantList ResetVks() const;
    void         SetResetVks(const QVariantList& vks);
    QString      Label() const;

    Q_INVOKABLE void Begin();
    Q_INVOKABLE void Reset();

signals:
    void changed();

protected:
    void keyPressEvent(QKeyEvent* event) override;
    void keyReleaseEvent(QKeyEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    void End(bool commit);

    std::vector<uint8_t> vks_;
    std::vector<uint8_t> reset_vks_;
    std::vector<uint8_t> pending_;
    std::vector<uint8_t> held_;
    bool                 capturing_ = false;
};
