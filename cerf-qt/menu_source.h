#pragma once

#include <QStringList>
#include <QVariantList>

class QObject;

class MenuSource {
public:
    virtual QStringList  MenuTitles() const                = 0;
    virtual QVariantList Menu(int index, QObject* menu)    = 0;
    virtual void         MenuPicked(QObject* menu, int id) = 0;

protected:
    ~MenuSource() = default;
};
