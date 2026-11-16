import QtQuick
import CerfStyle

PageWindow {
    readonly property int fixedWidth: 400
    property real contentHeight: 0

    width: fixedWidth
    height: contentHeight
    minimumWidth: fixedWidth
    maximumWidth: fixedWidth
    minimumHeight: contentHeight
    maximumHeight: contentHeight
}
