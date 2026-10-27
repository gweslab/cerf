import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ScrollView {
    id: scroll
    property int margins: Theme.spaceXXL
    default property alias content: column.data

    spacing: Theme.spaceL
    contentWidth: availableWidth
    contentHeight: frame.implicitHeight

    ColumnLayout {
        id: frame
        width: scroll.availableWidth

        ColumnLayout {
            id: column
            Layout.fillWidth: true
            Layout.margins: scroll.margins
            spacing: scroll.spacing
        }
    }
}
