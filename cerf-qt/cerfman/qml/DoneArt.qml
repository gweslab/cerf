import QtQuick
import CerfStyle

Item {
    id: art
    readonly property int discSize: 112
    readonly property int markSize: 72

    Rectangle {
        anchors.centerIn: parent
        width: art.discSize
        height: art.discSize
        radius: art.discSize / 2
        color: Theme.success

        SymbolIcon {
            anchors.centerIn: parent
            name: "check"
            size: art.markSize
            color: Theme.successMark
        }
    }
}
