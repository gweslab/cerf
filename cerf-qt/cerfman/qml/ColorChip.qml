import QtQuick
import CerfStyle

PreviewLabel {
    id: chip

    visible: text !== ""
    color: Theme.previewText
    leftPadding: Theme.spaceS
    rightPadding: Theme.spaceS
    topPadding: Theme.spaceXXS
    bottomPadding: Theme.spaceXXS
    background: Rectangle {
        radius: height / 2
        color: Theme.chipColor(chip.text)
    }
}
