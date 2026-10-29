import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ScrollView {
    id: scroll
    property int margins: Theme.spaceXXL
    property bool centered: false
    default property alias content: column.data

    spacing: Theme.spaceL
    contentWidth: availableWidth
    contentHeight: frame.implicitHeight

    ColumnLayout {
        id: frame
        width: scroll.availableWidth
        height: scroll.centered ? Math.max(implicitHeight, scroll.availableHeight) : implicitHeight
        spacing: 0

        Item {
            visible: scroll.centered
            Layout.fillHeight: true
        }
        ColumnLayout {
            id: column
            Layout.fillWidth: true
            Layout.maximumWidth: Number.POSITIVE_INFINITY
            Layout.fillHeight: false
            Layout.margins: scroll.margins
            spacing: scroll.spacing
        }
        Item {
            visible: scroll.centered
            Layout.fillHeight: true
        }
    }
}
