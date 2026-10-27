import QtQuick
import QtQuick.Controls.Material
import CerfStyle

LinkAwareLabel {
    property bool dim: false
    property bool warning: false

    color: warning ? Theme.warn : dim ? Theme.dim : Material.foreground
    textFormat: Text.StyledText
    wrapMode: Text.Wrap
}
