import QtQuick
import QtQuick.Controls
import CerfStyle

Item {
    id: feature
    property string icon: ""
    property string tip: ""
    property int size: 32
    readonly property real badgeShare: 0.42
    readonly property real ringShare: 0.08
    readonly property real crossArmShare: 0.4
    readonly property real crossWeightShare: 0.14
    readonly property real unsupportedOpacity: 0.73
    readonly property int badge: Math.round(size * badgeShare)
    readonly property real ring: badge * ringShare
    readonly property real crossLength: badge * crossArmShare * Math.SQRT2
    readonly property real crossWeight: badge * crossWeightShare

    implicitWidth: size
    implicitHeight: size

    Image {
        anchors.fill: parent
        source: IconSources.Asset(feature.icon)
        sourceSize: Qt.size(feature.size, feature.size)
        opacity: feature.unsupportedOpacity
    }

    Item {
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        width: feature.badge
        height: feature.badge

        Rectangle {
            anchors.fill: parent
            radius: width / 2
            color: Theme.noticeMark
        }
        Rectangle {
            anchors.fill: parent
            anchors.margins: feature.ring
            radius: width / 2
            color: Theme.notice
        }
        Repeater {
            model: [45, -45]
            delegate: Rectangle {
                required property int modelData
                anchors.centerIn: parent
                width: feature.crossLength
                height: feature.crossWeight
                rotation: modelData
                color: Theme.noticeMark
            }
        }
    }

    HoverHandler {
        id: hover
    }
    ToolTip.visible: hover.hovered
    ToolTip.text: feature.tip
    ToolTip.delay: 400
}
