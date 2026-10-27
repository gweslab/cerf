import QtQuick
import QtQuick.Controls

SettingsRow {
    id: row
    property alias checked: toggle.checked
    property alias editable: toggle.enabled
    signal toggled()

    wideControl: false

    Switch {
        id: toggle
        onToggled: row.toggled()
    }
}
