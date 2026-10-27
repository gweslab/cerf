import QtQuick
import QtQuick.Controls

ApplicationWindow {
    id: win
    property bool modal: true

    function center() {
        if (transientParent !== null) {
            x = transientParent.x + (transientParent.width - width) / 2
            y = transientParent.y + (transientParent.height - height) / 2
        } else {
            x = Screen.virtualX + (Screen.width - width) / 2
            y = Screen.virtualY + (Screen.height - height) / 2
        }
    }

    modality: modal ? Qt.ApplicationModal : Qt.NonModal

    Component.onCompleted: {
        WindowLifetime.DeleteWhenClosed(win)
        center()
    }
}
