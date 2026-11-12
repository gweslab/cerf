import QtQuick
import QtQuick.Controls.Material as M

M.MenuBar {
    delegate: MenuBarItem {}
    implicitHeight: contentHeight + topPadding + bottomPadding
    background: null
}
