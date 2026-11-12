import QtQuick
import QtQuick.Layouts
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.MenuItem {
    id: control
    readonly property real leadingRoom: checkable && indicator ? indicator.width + spacing : 0
    readonly property real trailingRoom: subMenu && arrow ? arrow.width + spacing : 0
    readonly property int tabAt: text.indexOf("\t")
    readonly property string label: tabAt < 0 ? text : text.substring(0, tabAt)
    readonly property string shortcutText: tabAt < 0 ? "" : text.substring(tabAt + 1)
    height: visible ? implicitHeight : 0

    Binding {
        target: control
        property: "hoverEnabled"
        value: false
        when: control.menu !== null && !control.menu.pointerMoved
    }

    HoverHandler {
        onPointChanged: {
            if (!hovered)
                return
            const at = control.mapToGlobal(point.position)
            control.menu.notePointer(at)
            if (control.subMenu !== null)
                control.subMenu.noteOpenerPointer(at)
        }
        onHoveredChanged: {
            if (!hovered && control.subMenu !== null)
                control.subMenu.forgetOpenerPointer()
        }
    }

    contentItem: RowLayout {
        spacing: Theme.spaceL
        layoutDirection: control.mirrored ? Qt.RightToLeft : Qt.LeftToRight

        Text {
            Layout.fillWidth: true
            leftPadding: control.mirrored ? (control.shortcutText === "" ? control.trailingRoom : 0) : control.leadingRoom
            rightPadding: control.mirrored ? control.leadingRoom : (control.shortcutText === "" ? control.trailingRoom : 0)
            text: control.label
            font: control.font
            color: enabled ? control.Material.foreground : control.Material.hintTextColor
            wrapMode: Text.Wrap
            verticalAlignment: Text.AlignVCenter
            horizontalAlignment: control.mirrored ? Text.AlignRight : Text.AlignLeft
        }

        Text {
            visible: control.shortcutText !== ""
            leftPadding: control.mirrored ? control.trailingRoom : 0
            rightPadding: control.mirrored ? 0 : control.trailingRoom
            text: control.shortcutText
            font: control.font
            color: control.Material.hintTextColor
            verticalAlignment: Text.AlignVCenter
        }
    }
}
