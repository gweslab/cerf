import QtQuick
import QtQuick.Controls.Material as M

M.ComboBox {
    id: comboBox

    WindowInsets.gap: Theme.spaceXL
    popup.leftMargin: WindowInsets.left
    popup.topMargin: WindowInsets.topMargin
    popup.rightMargin: WindowInsets.right
    popup.bottomMargin: WindowInsets.bottomMargin

    background: FieldBackground {
        control: comboBox
        visible: !comboBox.flat
    }
}
