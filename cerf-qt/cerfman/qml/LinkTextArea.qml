import QtQuick
import QtQuick.Controls

TextArea {
    readOnly: true
    selectByMouse: true
    wrapMode: TextEdit.Wrap
    onLinkActivated: link => DesktopShell.OpenLink(link)

    LinkCursor {
        idleShape: Qt.IBeamCursor
    }
}
