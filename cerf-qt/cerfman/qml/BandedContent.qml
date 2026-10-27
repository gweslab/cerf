import QtQuick
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    default property alias content: body.data
    property alias contentSpacing: body.spacing

    spacing: 0

    AboutBand {}

    ColumnLayout {
        id: body
        Layout.fillWidth: true
        Layout.margins: Theme.spaceXXXL
    }
}
