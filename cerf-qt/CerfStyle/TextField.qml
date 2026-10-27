import QtQuick
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.TextField {
    id: control

    topPadding: Material.textFieldVerticalPadding

    background: FieldBackground {
        control: control
    }

    TextMenuTap {}
}
