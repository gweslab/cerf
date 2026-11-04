#pragma once

#include <QToolButton>

class QtHudButton : public QToolButton {
public:
    explicit QtHudButton(QWidget* parent);

protected:
    void changeEvent(QEvent* event) override;

private:
    void Tint();
};
