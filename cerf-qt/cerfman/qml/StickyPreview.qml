import QtQuick
import QtQuick.Controls
import CerfStyle

Control {
    id: band
    property var row: null
    property real previewHeight: 0
    property real restHeight: 0
    signal clicked()

    padding: 0
    background: Rectangle {
        color: Theme.pageBg
    }
    contentItem: DevicePreview {
        implicitHeight: band.previewHeight
        row: band.row
        detailed: true
        actionEnabled: band.enabled
        restHeight: band.restHeight
        onLaunch: band.clicked()
    }
}
