import QtQuick
import CerfStyle

PageWindow {
    id: host
    signal finished()

    title: qsTr("Tutorial")
    width: 640
    height: 560
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    TutorialView {
        anchors.fill: parent
        onFinished: {
            host.finished()
            host.close()
        }
    }
}
