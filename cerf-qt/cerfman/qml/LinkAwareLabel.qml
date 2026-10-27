import QtQuick
import QtQuick.Controls

Label {
    id: label
    signal anchorActivated(string link)

    onLinkActivated: link => {
        if (!DesktopShell.OpenLink(link))
            label.anchorActivated(link)
    }

    LinkCursor {}
}
