import QtQuick
import CerfStyle

Rectangle {
    readonly property int diameter: 8

    implicitWidth: diameter
    implicitHeight: diameter
    width: diameter
    height: diameter
    radius: diameter / 2
    color: Theme.notice
}
