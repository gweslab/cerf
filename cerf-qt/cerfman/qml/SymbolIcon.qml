import QtQuick
import QtQuick.Controls.Material

Image {
    property string name
    property color color: Material.foreground
    property int size: 20

    width: size
    height: size
    sourceSize: Qt.size(size, size)
    source: size > 0 ? IconSources.Tinted(name, color) : ""
}
