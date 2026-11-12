#pragma once

#include "menu_source.h"
#include "strip_press_delay.h"

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QStringList>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

class EmulatorController : public QObject, public StripPressReceiver, public MenuSource {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(int rowHoldMs READ RowHoldMs CONSTANT)
    Q_PROPERTY(bool hudAvailable READ HudAvailable NOTIFY hudChanged)
    Q_PROPERTY(bool hudShown READ HudShown NOTIFY hudChanged)
    Q_PROPERTY(QStringList menuTitles READ MenuTitles NOTIFY menusChanged)

public:
    using QObject::QObject;

    int         RowHoldMs() const;
    bool        HudAvailable() const;
    bool        HudShown() const;
    QStringList MenuTitles() const override;
    void        RefreshHud() { emit hudChanged(); }

    void Attach(cerfcore::CerfEmulator& emu) {
        gate_.Attach(emu);
        emit hudChanged();
        emit menusChanged();
    }
    void Detach() {
        row_press_.Drop();
        gate_ = cerfcore::InstanceGate();
    }

    Q_INVOKABLE void OpenGearMenu(qreal x, qreal y);
    Q_INVOKABLE void OpenPointerMenu(qreal x, qreal y);
    Q_INVOKABLE void MenuPicked(QObject* menu, int id) override;
    Q_INVOKABLE void MenuClosing();
    Q_INVOKABLE void RequestClose();
    Q_INVOKABLE QVariantList RowButtons(bool keyboard_open);
    Q_INVOKABLE void PressRowButton(int index);
    Q_INVOKABLE void ReleaseRowButton(int index);
    Q_INVOKABLE void CancelRowButton(int index);
    Q_INVOKABLE bool HoldRowButton(int index);
    Q_INVOKABLE void ToggleHud();
    Q_INVOKABLE QVariantList Menu(int index, QObject* menu) override;
    Q_INVOKABLE void RefitWindow();

signals:
    void hudChanged();
    void menusChanged();

private:
    void OnStripStep(StripPressDelay::Step step, int index) override;

    cerfcore::InstanceGate gate_;
    StripPressDelay        row_press_{*this};
};
