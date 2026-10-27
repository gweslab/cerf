import QtQuick
import QtQuick.Controls

PopupDialog {
    id: dialog
    signal ok()

    closePolicy: Popup.CloseOnEscape

    rightToLeftButtons: [
        Button {
            text: qsTr("Cancel")
            onClicked: dialog.close()
        },
        Button {
            text: qsTr("OK")
            highlighted: true
            onClicked: dialog.ok()
        }
    ]
}
