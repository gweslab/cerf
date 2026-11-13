import QtQuick
import CerfStyle

ApplicationWindow {
    id: win
    readonly property bool modalChildren: modalOver(transientParent)
    property bool modal: modalChildren

    function modalOver(owner) {
        return owner === null || owner.modalChildren !== false
    }

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
