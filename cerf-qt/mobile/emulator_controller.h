#pragma once

#include "strip_press_delay.h"

#include <QObject>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

namespace cerfcore {
class CerfEmulator;
}

class EmulatorController : public QObject {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(int rowHoldMs READ RowHoldMs CONSTANT)

public:
    using QObject::QObject;

    int RowHoldMs() const;

    void Attach(cerfcore::CerfEmulator& emu) { emu_ = &emu; }
    void Detach() {
        row_press_.Drop();
        emu_ = nullptr;
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
    void RowStep(StripPressDelay::Step step, int index);

    cerfcore::CerfEmulator* emu_ = nullptr;
    StripPressDelay         row_press_{[this](StripPressDelay::Step step, int index) { RowStep(step, index); }};
};
