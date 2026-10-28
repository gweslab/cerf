import QtQuick
import QtQuick.Controls.Material as M
import QtQuick.Templates as T

M.Dialog {
    T.Overlay.modal: Rectangle {
        color: Theme.backdrop
        Behavior on opacity { NumberAnimation { duration: Theme.morphMs } }
    }
    T.Overlay.modeless: Rectangle {
        color: Theme.backdrop
        Behavior on opacity { NumberAnimation { duration: Theme.morphMs } }
    }
}
