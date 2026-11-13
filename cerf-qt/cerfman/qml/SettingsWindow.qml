import QtQuick
import CerfStyle

PageWindow {
    id: host
    property alias deviceLine: view.deviceLine

    function showPage(key) {
        view.show(key)
    }

    title: view.title
    width: 820
    height: 560
    minimumWidth: Theme.sheetWindowMinimumWidth
    minimumHeight: Theme.sheetWindowMinimumHeight

    SettingsView {
        id: view
        anchors.fill: parent
        onClosed: host.close()
    }
}
