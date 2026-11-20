import QtQuick
import CerfStyle

Item {
    id: feature
    property string icon: ""
    property string tip: ""
    property int size: 32
    readonly property real badgeShare: 0.42
    readonly property real unsupportedOpacity: 0.73
    readonly property int badge: Math.round(size * badgeShare)

    implicitWidth: size
    implicitHeight: size

    Image {
        anchors.fill: parent
        source: IconSources.Asset(feature.icon)
        sourceSize: Qt.size(feature.size, feature.size)
        opacity: feature.unsupportedOpacity
    }

    Image {
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        width: feature.badge
        height: feature.badge
        source: IconSources.Asset("unsupported_badge")
        sourceSize: Qt.size(feature.badge, feature.badge)
    }

    HoverHandler {
        id: hover
    }
    ToolTip.visible: hover.hovered
    ToolTip.text: feature.tip
    ToolTip.delay: Theme.tipDelayMs
}
