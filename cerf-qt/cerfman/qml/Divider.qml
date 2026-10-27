import QtQuick
import CerfStyle

Rectangle {
    property bool vertical: false

    implicitWidth: vertical ? Theme.hairline : 0
    implicitHeight: vertical ? 0 : Theme.hairline
    color: Theme.divider
}
