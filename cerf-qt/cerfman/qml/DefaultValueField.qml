import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import CerfStyle

TextField {
    property bool showingDefault: false

    color: showingDefault ? Theme.dim : Material.foreground
}
