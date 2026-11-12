#pragma once

#include <QObject>

#include <memory>

class MenuSource;
class QWindow;

class GlobalMenuBar : public QObject {
public:
    struct Native;

    GlobalMenuBar(QWindow& window, MenuSource& source);
    ~GlobalMenuBar() override;

private:
    std::unique_ptr<Native> native_;
};
