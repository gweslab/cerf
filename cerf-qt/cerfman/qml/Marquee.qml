import QtQuick
import QtQuick.Controls

Item {
    id: marquee
    property string text: ""
    property string separator: ""
    property real gap: 0
    property Component label: plainLabel
    property real speed: 34
    property int startDelay: 2500
    readonly property real textWidth: probe.item !== null ? probe.item.implicitWidth : 0
    readonly property bool scrolling: textWidth > width
    readonly property bool moving: scrolling && visible
    property real offset: 0

    implicitHeight: probe.implicitHeight
    clip: true

    onMovingChanged: {
        if (moving)
            return
        scroll.stop()
        offset = 0
    }

    Component {
        id: plainLabel
        Label {}
    }

    Loader {
        id: probe
        sourceComponent: marquee.label
        visible: !marquee.scrolling
    }
    Binding {
        target: probe.item
        property: "text"
        value: marquee.text
        when: probe.item !== null
    }

    Row {
        visible: marquee.scrolling
        x: -marquee.offset
        spacing: marquee.gap

        Loader {
            id: cycle
            sourceComponent: marquee.label
        }
        Loader {
            id: copy
            sourceComponent: marquee.label
        }
    }
    Binding {
        target: cycle.item
        property: "text"
        value: marquee.text + marquee.separator
        when: cycle.item !== null
    }
    Binding {
        target: copy.item
        property: "text"
        value: marquee.text + marquee.separator
        when: copy.item !== null
    }

    Timer {
        interval: marquee.startDelay
        running: marquee.moving
        onTriggered: scroll.start()
    }

    NumberAnimation {
        id: scroll
        target: marquee
        property: "offset"
        from: 0
        to: cycle.implicitWidth + marquee.gap
        duration: (cycle.implicitWidth + marquee.gap) / marquee.speed * 1000
        loops: Animation.Infinite
    }
}
