import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: block
    property string title
    property bool warn: false
    property bool clickable: false
    readonly property real bodyWidth: body.width
    readonly property int iconSize: 16
    default property alias content: body.data
    signal clicked()

    spacing: Theme.spaceS

    RowLayout {
        spacing: Theme.spaceXS

        SymbolIcon {
            visible: block.warn
            name: "warning"
            size: block.iconSize
            color: Theme.warn
        }
        StrongLabel {
            text: block.title
            warning: block.warn
        }
    }

    Card {
        id: card
        Layout.fillWidth: true
        padding: 0
        hoverEnabled: block.clickable

        RowLayout {
            Layout.fillWidth: true
            Layout.margins: Theme.spaceL
            spacing: Theme.spaceS

            ColumnLayout {
                id: body
                Layout.fillWidth: true
                spacing: Theme.spaceXS
            }
            SymbolIcon {
                visible: block.clickable
                name: "chevron_right"
                size: block.iconSize
                color: Theme.dim
            }
        }

        HoverHandler {
            enabled: block.clickable
            cursorShape: Qt.PointingHandCursor
        }

        TapHandler {
            enabled: block.clickable
            onTapped: block.clicked()
        }
    }
}
