import QtQuick
import CerfStyle

Label {
    property bool dim: false
    property bool warning: false

    font.bold: true
    color: warning ? Theme.warn : dim ? Theme.dim : Material.foreground
}
