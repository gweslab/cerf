import QtQuick
import QtQuick.Controls.Material as M

M.ComboBox {
    id: control

    WindowInsets.gap: Theme.spaceXL
    popup.leftMargin: WindowInsets.left
    popup.topMargin: WindowInsets.topMargin
    popup.rightMargin: WindowInsets.right
    popup.bottomMargin: WindowInsets.bottomMargin

    background: FieldBackground {
        control: control
        visible: !control.flat
    }
}
