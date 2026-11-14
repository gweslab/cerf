import QtQuick
import QtQuick.Layouts
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.Button {
    id: control

    icon.color: !enabled ? Material.hintTextColor
              : highlighted && !flat ? Theme.onAccent
              : (flat && highlighted) || (checked && !highlighted) ? Material.accentColor
              : Material.foreground

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight

        RowLayout {
            id: row
            anchors.centerIn: parent
            width: Math.min(implicitWidth, parent.width)
            spacing: control.spacing
            layoutDirection: control.mirrored ? Qt.RightToLeft : Qt.LeftToRight

            ControlIcon {
                symbol: control.icon.source
                tint: control.icon.color
                iconSize: Qt.size(control.icon.width, control.icon.height)
            }
            Text {
                Layout.fillWidth: true
                text: control.text
                font: control.font
                color: control.icon.color
                elide: Text.ElideRight
                horizontalAlignment: Text.AlignHCenter
            }
        }
    }
}
