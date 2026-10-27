import QtQuick
import QtQuick.Controls.Material
import CerfStyle

LinkAwareLabel {
    property bool dim: true

    color: dim ? Theme.dim : Material.foreground
    font.pixelSize: Theme.captionSize
}
