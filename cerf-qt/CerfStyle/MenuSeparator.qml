import QtQuick
import QtQuick.Controls.Material as M

M.MenuSeparator {
    id: control
    height: visible ? implicitHeight : 0

    Binding {
        target: control
        property: "verticalPadding"
        value: Theme.spaceXS
        when: !Theme.touchPlatform
    }
}
