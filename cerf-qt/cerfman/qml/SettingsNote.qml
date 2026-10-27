import QtQuick
import QtQuick.Layouts
import CerfStyle

SettingsItem {
    id: note
    property string text
    readonly property int iconSize: 18

    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.spaceXL

        SymbolIcon {
            Layout.alignment: Qt.AlignTop
            name: "info"
            size: note.iconSize
            color: Theme.dim
        }
        SecondaryLabel {
            Layout.fillWidth: true
            text: note.text
            wrapMode: Text.Wrap
        }
    }
}
