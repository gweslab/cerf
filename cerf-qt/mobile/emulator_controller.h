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

public:
    using QObject::QObject;

    int RowHoldMs() const;

    void Attach(cerfcore::CerfEmulator& emu) { gate_.Attach(emu); }
    void Detach() {
        row_press_.Drop();
        gate_ = cerfcore::InstanceGate();
    }

    Q_INVOKABLE void OpenGearMenu(qreal x, qreal y);
    Q_INVOKABLE void OpenPointerMenu(qreal x, qreal y);
    Q_INVOKABLE void MenuPicked(int id);
    Q_INVOKABLE void RequestClose();
    Q_INVOKABLE QVariantList RowButtons();
    Q_INVOKABLE void PressRowButton(int index);
    Q_INVOKABLE void ReleaseRowButton(int index);
    Q_INVOKABLE void CancelRowButton(int index);
    Q_INVOKABLE bool HoldRowButton(int index);

private:
    void OnStripStep(StripPressDelay::Step step, int index) override;

    cerfcore::InstanceGate gate_;
    StripPressDelay        row_press_{*this};
};
