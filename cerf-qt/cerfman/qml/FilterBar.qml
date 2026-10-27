import QtQuick
import QtQuick.Controls
import CerfStyle

Pane {
    default property alias content: flow.data

    padding: Theme.spaceM

    background: Rectangle {
        color: Theme.barBg
    }

    Flow {
        id: flow
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: Theme.spaceM
    }
}
