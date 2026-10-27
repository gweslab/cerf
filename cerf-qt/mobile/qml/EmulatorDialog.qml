import QtQuick
import QtQuick.Controls

PopupDialog {
    property var texts: ({})
    property var chosen: null
    signal finished(var chosen)

    focus: true
    closePolicy: Popup.CloseOnEscape
    title: texts.title

    onClosed: {
        finished(chosen)
        destroy()
    }
}
