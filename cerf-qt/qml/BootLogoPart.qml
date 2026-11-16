import QtQuick

Item {
    id: piece
    property var part
    property QtObject parts
    property real logoSize
    property point pixelScale: Qt.point(1, 1)
    property point origin: Qt.point(0, 0)
    property real startScale: 1
    property real startShift: 0
    property int delay: 0
    property int duration: 0
    property var curve: []
    property int fadeDuration: 0
    property var fadeCurve: []
    property bool paused: false

    function play() {
        entrance.restart()
    }

    function settle() {
        entrance.stop()
        opacity = 1
        x = 0
        image.scale = 1
    }

    readonly property var placement: {
        const across = logoSize * pixelScale.x
        const down = logoSize * pixelScale.y
        const left = Math.floor(part.x * across)
        const top = Math.floor(part.y * down)
        const pixels = Qt.rect(left, top, Math.ceil((part.x + part.width) * across) - left,
                               Math.ceil((part.y + part.height) * down) - top)
        return {
            frame: Qt.rect(left / pixelScale.x - origin.x, top / pixelScale.y - origin.y, pixels.width / pixelScale.x,
                           pixels.height / pixelScale.y),
            source: logoSize > 0 ? parts.RegionSource(part.asset, Qt.size(across, down), pixels) : ""
        }
    }

    Image {
        id: image
        x: piece.placement.frame.x
        y: piece.placement.frame.y
        width: piece.placement.frame.width
        height: piece.placement.frame.height
        source: piece.placement.source
    }

    SequentialAnimation {
        id: entrance
        paused: running && piece.paused
        PropertyAction {
            target: piece
            property: "opacity"
            value: 0
        }
        PropertyAction {
            target: image
            property: "scale"
            value: piece.startScale
        }
        PropertyAction {
            target: piece
            property: "x"
            value: piece.startShift
        }
        PauseAnimation {
            duration: piece.delay
        }
        ParallelAnimation {
            NumberAnimation {
                target: piece
                property: "opacity"
                from: 0
                to: 1
                duration: piece.fadeDuration
                easing.type: Easing.BezierSpline
                easing.bezierCurve: piece.fadeCurve
            }
            NumberAnimation {
                target: image
                property: "scale"
                from: piece.startScale
                to: 1
                duration: piece.duration
                easing.type: Easing.BezierSpline
                easing.bezierCurve: piece.curve
            }
            NumberAnimation {
                target: piece
                property: "x"
                from: piece.startShift
                to: 0
                duration: piece.duration
                easing.type: Easing.BezierSpline
                easing.bezierCurve: piece.curve
            }
        }
    }
}
