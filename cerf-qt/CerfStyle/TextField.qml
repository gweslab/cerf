import QtQuick
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.TextField {
    id: textField

    topPadding: Material.textFieldVerticalPadding

    background: FieldBackground {
        control: textField
    }

    TextMenuTap {}
}
