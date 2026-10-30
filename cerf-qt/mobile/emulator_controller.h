#pragma once

#include "strip_press_delay.h"

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

class EmulatorController : public QObject, public StripPressReceiver {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(int rowHoldMs READ RowHoldMs CONSTANT)
    Q_PROPERTY(bool hudAvailable READ HudAvailable NOTIFY hudChanged)
    Q_PROPERTY(bool hudShown READ HudShown NOTIFY hudChanged)

public:
    using QObject::QObject;

    int  RowHoldMs() const;
    bool HudAvailable() const;
    bool HudShown() const;
    void RefreshHud() { emit hudChanged(); }

    void Attach(cerfcore::CerfEmulator& emu) {
        gate_.Attach(emu);
        emit hudChanged();
    }
    void Detach() {
        row_press_.Drop();
        gate_ = cerfcore::InstanceGate();
    }

    Q_INVOKABLE void OpenGearMenu(qreal x, qreal y);
    Q_INVOKABLE void OpenPointerMenu(qreal x, qreal y);
    Q_INVOKABLE void MenuPicked(int id);
    Q_INVOKABLE void RequestClose();
    Q_INVOKABLE QVariantList RowButtons(bool keyboard_open);
    Q_INVOKABLE void PressRowButton(int index);
    Q_INVOKABLE void ReleaseRowButton(int index);
    Q_INVOKABLE void CancelRowButton(int index);
    Q_INVOKABLE bool HoldRowButton(int index);
    Q_INVOKABLE void ToggleHud();

signals:
    void hudChanged();

private:
    void OnStripStep(StripPressDelay::Step step, int index) override;

    cerfcore::InstanceGate gate_;
    StripPressDelay        row_press_{*this};
};
