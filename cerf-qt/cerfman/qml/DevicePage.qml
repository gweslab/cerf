import QtQuick
import QtQuick.Controls

Page {
    id: page
    required property QtObject commands
    property alias row: panel.row
    property alias busy: panel.busy
    property alias revision: panel.revision
    signal back()

    header: PageBar {
        title: page.row ? page.row.title : ""
        onBack: page.back()
    }

    DevicePanel {
        id: panel
        anchors.fill: parent
        commands: page.commands
    }
}
