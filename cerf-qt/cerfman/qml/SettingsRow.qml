import QtQuick
import QtQuick.Layouts

SettingsItem {
    id: row
    property alias title: option.title
    property alias description: option.description
    property alias wideControl: option.wideControl
    default property alias control: option.control
    signal anchorActivated(string link)

    OptionRow {
        id: option
        Layout.fillWidth: true
        onAnchorActivated: link => row.anchorActivated(link)
    }
}
