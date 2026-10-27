import QtQuick
import QtQuick.Controls

Item {
    id: marquee
    property string text: ""
    property string separator: ""
    property real speed: 34
    property int startDelay: 2500
    readonly property bool scrolling: probe.implicitWidth > width
    property real offset: 0

    implicitHeight: probe.implicitHeight
    clip: true

    Label {
        id: probe
        visible: !marquee.scrolling
        text: marquee.text
    }

    Row {
        visible: marquee.scrolling
        x: -marquee.offset

        Label {
            id: cycle
            text: marquee.text + marquee.separator
        }
        Label {
            text: cycle.text
        }
    }

    Timer {
        interval: marquee.startDelay
        running: marquee.scrolling && marquee.visible
        onTriggered: scroll.start()
    }

    NumberAnimation {
        id: scroll
        target: marquee
        property: "offset"
        from: 0
        to: cycle.implicitWidth
        duration: cycle.implicitWidth / marquee.speed * 1000
        loops: Animation.Infinite
    }
}
