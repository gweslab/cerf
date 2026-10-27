import QtQuick
import QtQuick.Controls.Material as M

M.Menu {
    id: control

    leftMargin: WindowInsets.leftMargin
    topMargin: WindowInsets.topMargin
    rightMargin: WindowInsets.rightMargin
    bottomMargin: WindowInsets.bottomMargin

    contentWidth: {
        let widest = 0
        for (let i = 0; i < count; ++i)
            widest = Math.max(widest, itemAt(i).implicitWidth)
        return widest
    }
}
