#pragma once

#include <QFontMetrics>
#include <QRect>

class QtDialogUnits {
public:
    explicit QtDialogUnits(const QFontMetrics& fm)
        : base_x_(fm.averageCharWidth()), base_y_(fm.height()) {}

    int   X(int unit) const { return MulDiv(unit, base_x_, 4); }
    int   Y(int unit) const { return MulDiv(unit, base_y_, 8); }
    QRect Rect(int x, int y, int w, int h) const { return QRect(X(x), Y(y), X(w), Y(h)); }

private:
    static int MulDiv(int a, int b, int c) { return (a * b + c / 2) / c; }

    int base_x_;
    int base_y_;
};
