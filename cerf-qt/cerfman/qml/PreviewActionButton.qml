import QtQuick
import QtQuick.Controls
import CerfStyle

AbstractButton {
    id: button
    property string runState: DeviceCards.offState
    property real discSize: Theme.previewDiscSize

    implicitWidth: discSize
    implicitHeight: discSize
    hoverEnabled: true

    background: Rectangle {
        radius: width / 2
        color: Theme.previewDisc
    }
    contentItem: Item {
        SymbolIcon {
            anchors.centerIn: parent
            size: Math.min(Theme.previewGlyphSize, button.discSize)
            name: button.runState === DeviceCards.savedState ? IconSources.resumeSymbol : IconSources.launchSymbol
            color: button.runState === DeviceCards.runningState ? Theme.previewRunning
                 : button.runState === DeviceCards.savedState ? Theme.previewSaved
                 : Theme.previewStopped
        }
    }

    HoverHandler {
        cursorShape: Qt.PointingHandCursor
    }
}
