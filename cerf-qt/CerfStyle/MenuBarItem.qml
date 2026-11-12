import QtQuick
import QtQuick.Controls.Material as M

M.MenuBarItem {
    id: control

    topPadding: Theme.spaceXS
    bottomPadding: Theme.spaceXS
    leftPadding: Theme.spaceM
    rightPadding: Theme.spaceM
    implicitHeight: implicitContentHeight + topPadding + bottomPadding

    background: Rectangle {
        color: control.highlighted ? Theme.windowBarHover : Theme.noFill
    }
}
