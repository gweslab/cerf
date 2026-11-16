import QtQuick
import QtQuick.Shapes
import CerfStyle

Rectangle {
    id: root
    property QtObject view
    property string uiFamily
    property string monoFamily
    property point pixelScale: Qt.point(1, 1)

    readonly property int logoMinSize: 112
    readonly property int logoMaxSize: 256
    readonly property real logoScreenPart: 0.4
    readonly property real labelGapPart: 0.14
    readonly property real glowRadiusPart: 1.9
    readonly property int frameMs: 600
    readonly property real frameStartScale: 0.9
    readonly property int plateMs: 450
    readonly property int plateStaggerMs: 50
    readonly property real plateShiftPart: 70 / 1024
    readonly property int boxesAtMs: 150
    readonly property int boxMs: 420
    readonly property int boxStaggerMs: 60
    readonly property real partFadePart: 0.55
    readonly property real spinnerStartPart: 0.4
    readonly property int spinnerFadeInMs: 500
    readonly property int spinnerFadeOutMs: 450
    readonly property int spinnerTurnMs: 1800
    readonly property real spinnerDimOpacity: 0.35
    readonly property int labelHoldMs: 300
    readonly property int textFadeMs: 350
    readonly property var settleCurve: [0.16, 1, 0.3, 1, 1, 1]
    readonly property var popCurve: [0.34, 1.56, 0.64, 1, 1, 1]
    readonly property var fadeCurve: [0.25, 0.1, 0.25, 1, 1, 1]
    readonly property var pulseCurve: [0.42, 0, 0.58, 1, 1, 1]
    readonly property var linearCurve: [0, 0, 1, 1, 1, 1]
    readonly property int statusLineHeight: 16
    readonly property int statusGap: 4
    readonly property int stripRoom: 16
    readonly property int hitSlack: 2

    readonly property QtObject parts: view.bootLogo
    readonly property int lastWave: parts.boxes.reduce((last, box) => Math.max(last, box.row + box.column), 0)
    readonly property int introMs: Math.max(frameMs, boxesAtMs + lastWave * boxStaggerMs + boxMs,
                                            (parts.plates.length - 1) * plateStaggerMs + plateMs)

    property real textOpacity: 0
    property bool started: false
    property bool spinning: false

    readonly property bool statusShown: view.hwLine !== ""
    readonly property real contentBottom: status.y - statusGap
    readonly property real wantedLogo: Math.max(logoMinSize, Math.min(logoMaxSize, Math.floor(Math.min(width, height) * logoScreenPart)))
    readonly property real fitLogo: (contentBottom - height / 2 + Theme.bootLabelSize / 2 - label.implicitHeight)
                                    / (0.5 + labelGapPart / 2)
    readonly property int logoSize: Math.max(0, Math.min(wantedLogo, Math.floor(fitLogo)))
    readonly property real labelGap: logoSize * labelGapPart
    readonly property real rise: (labelGap + Theme.bootLabelSize) / 2 * textOpacity
    readonly property real labelRoom: contentBottom - label.implicitHeight - (logo.y + logo.height)
    readonly property rect hit: statusShown && visible ? Qt.rect(0, status.y - hitSlack, width, height - stripRoom - status.y + hitSlack)
                                            : Qt.rect(0, 0, 0, 0)

    function glowAt(position) {
        const t = 1 - position
        return Qt.rgba(Theme.bootGlow.r, Theme.bootGlow.g, Theme.bootGlow.b, t * t * (3 - 2 * t))
    }

    function eachPart(action) {
        action(frame)
        for (let i = 0; i < plates.count; ++i)
            action(plates.itemAt(i))
        for (let i = 0; i < boxes.count; ++i)
            action(boxes.itemAt(i))
    }

    function showSpinner(delay) {
        spinnerOut.stop()
        spinnerIn.delay = delay
        spinning = true
        spinnerIn.restart()
    }

    function hideSpinner() {
        spinnerIn.stop()
        spinnerOut.restart()
    }

    function begin() {
        if (started)
            return
        started = true
        if (view.latched)
            finish()
        else if (view.restartSerial !== 0)
            restart()
        else
            playIntro()
    }

    function playIntro() {
        textFade.stop()
        textOpacity = 0
        eachPart(part => part.play())
        statusFade.restart()
        intro.restart()
        showSpinner(frameMs * spinnerStartPart)
    }

    function restart() {
        intro.stop()
        statusFade.stop()
        status.opacity = 1
        eachPart(part => part.settle())
        textOpacity = 0
        textFade.restart()
        showSpinner(0)
    }

    function finish() {
        intro.stop()
        textFade.stop()
        statusFade.stop()
        status.opacity = 1
        eachPart(part => part.settle())
        textOpacity = 1
        hideSpinner()
    }

    color: Theme.canvasTabBg
    onHitChanged: view.PlaceHwLine(hit)
    onVisibleChanged: {
        if (visible)
            begin()
    }
    Component.onCompleted: {
        view.PlaceHwLine(hit)
        if (visible)
            begin()
    }

    Connections {
        target: root.view
        function onRestartSerialChanged() {
            if (root.started)
                root.restart()
        }
        function onLatchedChanged() {
            if (root.view.latched)
                root.finish()
        }
    }

    SequentialAnimation {
        id: intro
        paused: running && root.view.paused
        PauseAnimation {
            duration: root.introMs + root.labelHoldMs
        }
        NumberAnimation {
            target: root
            property: "textOpacity"
            from: 0
            to: 1
            duration: root.textFadeMs
        }
    }

    NumberAnimation {
        id: textFade
        paused: running && root.view.paused
        target: root
        property: "textOpacity"
        from: 0
        to: 1
        duration: root.textFadeMs
    }

    NumberAnimation {
        id: statusFade
        paused: running && root.view.paused
        target: status
        property: "opacity"
        from: 0
        to: 1
        duration: root.frameMs
    }

    SequentialAnimation {
        id: spinnerIn
        property int delay
        paused: running && root.view.paused
        PauseAnimation {
            duration: spinnerIn.delay
        }
        NumberAnimation {
            target: spinnerFade
            property: "opacity"
            from: 0
            to: 1
            duration: root.spinnerFadeInMs
            easing.type: Easing.BezierSpline
            easing.bezierCurve: root.fadeCurve
        }
    }

    NumberAnimation {
        id: spinnerOut
        paused: running && root.view.paused
        target: spinnerFade
        property: "opacity"
        to: 0
        duration: root.spinnerFadeOutMs
        easing.type: Easing.BezierSpline
        easing.bezierCurve: root.fadeCurve
        onFinished: root.spinning = false
    }

    RotationAnimation {
        target: spinnerTurn
        from: 0
        to: 360
        duration: root.spinnerTurnMs
        loops: Animation.Infinite
        running: root.spinning && root.visible
        paused: running && root.view.paused
    }

    SequentialAnimation {
        loops: Animation.Infinite
        running: root.spinning && root.visible
        paused: running && root.view.paused
        NumberAnimation {
            target: spinner
            property: "opacity"
            from: root.spinnerDimOpacity
            to: 1
            duration: root.spinnerTurnMs / 2
            easing.type: Easing.BezierSpline
            easing.bezierCurve: root.pulseCurve
        }
        NumberAnimation {
            target: spinner
            property: "opacity"
            from: 1
            to: root.spinnerDimOpacity
            duration: root.spinnerTurnMs / 2
            easing.type: Easing.BezierSpline
            easing.bezierCurve: root.pulseCurve
        }
    }

    Shape {
        id: glow
        readonly property real radius: root.logoSize * root.glowRadiusPart
        readonly property real centerX: logo.x + logo.width / 2
        readonly property real centerY: logo.y + logo.height / 2
        visible: radius > 1 && root.textOpacity > 0
        opacity: root.textOpacity
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
            strokeColor: Theme.noFill
            startX: glow.centerX - glow.radius
            startY: glow.centerY - glow.radius
            fillGradient: RadialGradient {
                centerX: glow.centerX
                centerY: glow.centerY
                centerRadius: glow.radius
                focalX: glow.centerX
                focalY: glow.centerY
                GradientStop { position: 0.0; color: root.glowAt(0.0) }
                GradientStop { position: 0.125; color: root.glowAt(0.125) }
                GradientStop { position: 0.25; color: root.glowAt(0.25) }
                GradientStop { position: 0.375; color: root.glowAt(0.375) }
                GradientStop { position: 0.5; color: root.glowAt(0.5) }
                GradientStop { position: 0.625; color: root.glowAt(0.625) }
                GradientStop { position: 0.75; color: root.glowAt(0.75) }
                GradientStop { position: 0.875; color: root.glowAt(0.875) }
                GradientStop { position: 1.0; color: root.glowAt(1.0) }
            }
            PathLine {
                x: glow.centerX + glow.radius
                y: glow.centerY - glow.radius
            }
            PathLine {
                x: glow.centerX + glow.radius
                y: glow.centerY + glow.radius
            }
            PathLine {
                x: glow.centerX - glow.radius
                y: glow.centerY + glow.radius
            }
            PathLine {
                x: glow.centerX - glow.radius
                y: glow.centerY - glow.radius
            }
        }
    }

    Item {
        id: logo
        anchors.centerIn: parent
        anchors.verticalCenterOffset: -root.rise
        width: root.logoSize
        height: root.logoSize
        visible: root.logoSize > 0
        transform: PixelSnap {
            target: logo
        }

        BootLogoPart {
            id: frame
            part: root.parts.frame
            parts: root.parts
            logoSize: logo.width
            pixelScale: root.pixelScale
            opacity: 0
            startScale: root.frameStartScale
            duration: root.frameMs
            curve: root.settleCurve
            fadeDuration: root.frameMs
            fadeCurve: root.settleCurve
            paused: root.view.paused
        }

        Item {
            id: spinnerFade
            anchors.fill: parent
            opacity: 0

            Item {
                id: spinnerTurn
                x: root.parts.spinner.x * logo.width
                y: root.parts.spinner.y * logo.height
                width: root.parts.spinner.width * logo.width
                height: root.parts.spinner.height * logo.height

                BootLogoPart {
                    id: spinner
                    part: root.parts.spinner
                    parts: root.parts
                    logoSize: logo.width
                    pixelScale: root.pixelScale
                    origin: Qt.point(spinnerTurn.x, spinnerTurn.y)
                }
            }
        }

        Repeater {
            id: plates
            model: root.parts.plates
            delegate: BootLogoPart {
                required property var modelData
                part: modelData
                parts: root.parts
                logoSize: logo.width
                pixelScale: root.pixelScale
                opacity: 0
                startShift: -root.plateShiftPart * logo.width
                delay: modelData.row * root.plateStaggerMs
                duration: root.plateMs
                curve: root.settleCurve
                fadeDuration: root.plateMs * root.partFadePart
                fadeCurve: root.linearCurve
                paused: root.view.paused
            }
        }

        Repeater {
            id: boxes
            model: root.parts.boxes
            delegate: BootLogoPart {
                required property var modelData
                part: modelData
                parts: root.parts
                logoSize: logo.width
                pixelScale: root.pixelScale
                opacity: 0
                startScale: 0
                delay: root.boxesAtMs + (modelData.row + modelData.column) * root.boxStaggerMs
                duration: root.boxMs
                curve: root.popCurve
                fadeDuration: root.boxMs * root.partFadePart
                fadeCurve: root.linearCurve
                paused: root.view.paused
            }
        }
    }

    Text {
        id: label
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: logo.bottom
        anchors.topMargin: Math.min(Math.floor(root.labelGap), root.labelRoom)
        opacity: root.textOpacity
        text: root.view.bootLabel
        textFormat: Text.PlainText
        horizontalAlignment: Text.AlignHCenter
        font.family: root.uiFamily
        font.pixelSize: Theme.bootLabelSize
        font.bold: true
        color: Theme.bootLabel
    }

    Text {
        id: status
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: Theme.spaceM
        anchors.rightMargin: Theme.spaceM
        anchors.bottomMargin: root.stripRoom + root.statusGap
        height: root.statusLineHeight
        visible: root.statusShown
        opacity: 0
        text: root.view.hwLine
        textFormat: Text.PlainText
        elide: Text.ElideRight
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        font.family: root.monoFamily
        font.pixelSize: Theme.bootStatusSize
        font.bold: true
        color: Theme.bootStatus
    }
}
