import QtQuick
import CerfStyle

PageWindow {
    id: dialog
    property var chosen: []
    signal toggled(string path, bool on)

    title: qsTr("Manage shaders")
    width: 720
    height: 600
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    ShaderPickerPage {
        anchors.fill: parent
        chosen: dialog.chosen
        footerBack: false
        onToggled: (path, on) => dialog.toggled(path, on)
        onCancel: dialog.close()
    }
}
