import QtQuick
import QtQuick.Controls

Button {
    id: button
    property var dialog: null
    text: qsTr("Safe Zone")
    onClicked: {
        const size = SafeZoneMetrics.SafeZonePixels(button)
        dialog.setValues([size.width, size.height])
    }
}
