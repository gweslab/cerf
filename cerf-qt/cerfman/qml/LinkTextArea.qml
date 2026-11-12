import QtQuick
import CerfStyle

TextArea {
    readOnly: true
    selectByMouse: true
    wrapMode: TextEdit.Wrap
    onLinkActivated: link => DesktopShell.OpenLink(link)

    LinkCursor {
        idleShape: Qt.IBeamCursor
    }
}
