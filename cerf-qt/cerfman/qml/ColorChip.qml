import QtQuick
import QtQuick.Controls
import CerfStyle

Control {
    id: chip
    property string text: ""

    visible: text !== ""
    leftPadding: Theme.spaceS
    rightPadding: Theme.spaceS
    topPadding: Theme.spaceXXS
    bottomPadding: Theme.spaceXXS
    implicitWidth: leftPadding + rightPadding + line.textWidth
    implicitHeight: topPadding + bottomPadding + line.implicitHeight
    background: Rectangle {
        radius: height / 2
        color: Theme.chipColor(chip.text)
    }
    contentItem: Marquee {
        id: line
        text: chip.text
        gap: Theme.spaceXL
        label: Component {
            PreviewLabel {
                color: Theme.previewText
            }
        }
    }
}
