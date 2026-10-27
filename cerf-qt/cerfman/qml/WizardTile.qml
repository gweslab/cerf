import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

AbstractButton {
    id: tile
    property string symbol
    property string title
    property string description
    readonly property int symbolSize: 40
    readonly property int descriptionWidth: 220

    hoverEnabled: true
    implicitHeight: 160
    padding: Theme.spaceM
    opacity: enabled ? 1 : 0.5

    background: CardBackground {
        hovered: tile.enabled && tile.hovered
    }

    contentItem: ColumnLayout {
        spacing: Theme.spaceS

        Item {
            Layout.fillHeight: true
        }
        SymbolIcon {
            Layout.alignment: Qt.AlignHCenter
            Layout.bottomMargin: Theme.spaceXS
            name: tile.symbol
            size: tile.symbolSize
        }
        TitleLabel {
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: tile.availableWidth
            level: TitleLabel.Tile
            text: tile.title
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        CaptionLabel {
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: Math.min(tile.descriptionWidth, tile.availableWidth)
            text: tile.description
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        Item {
            Layout.fillHeight: true
        }
    }

    HoverHandler {
        cursorShape: tile.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
    }
}
