import QtQuick
import CerfStyle

TextField {
    property bool showingDefault: false

    color: showingDefault ? Theme.dim : Material.foreground
}
