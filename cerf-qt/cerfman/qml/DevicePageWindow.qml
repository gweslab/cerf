import QtQuick
import CerfStyle

PageWindow {
    id: host
    required property Component page
    required property var properties

    width: 720
    height: 560
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    Component.onCompleted: {
        const content = page.createObject(host.contentItem, properties)
        content.anchors.fill = host.contentItem
        content.closed.connect(host.close)
        host.title = Qt.binding(() => content.title)
    }
}
