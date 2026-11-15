import QtQuick
import QtQuick.Shapes
import CerfStyle

Rectangle {
    id: root
    property QtObject view
    property string uiFamily
    property string monoFamily

    readonly property int logoMinSize: 96
    readonly property int logoMaxSize: 220
    readonly property real logoScreenPart: 1 / 3
    readonly property real labelGapPart: 0.14
    readonly property real glowRadiusPart: 1.9
    readonly property int logoFadeMs: 350
    readonly property int logoHoldMs: 1200
    readonly property int textFadeMs: 350
    readonly property int statusLineHeight: 16
    readonly property int statusGap: 4
    readonly property int stripRoom: 16
    readonly property int hitSlack: 2

    property real logoOpacity: 0
    property real textOpacity: 0
    property bool started: false

    readonly property bool statusShown: view.hwLine !== ""
    readonly property real contentBottom: status.y - statusGap
    readonly property real wantedLogo: Math.max(logoMinSize, Math.min(logoMaxSize, Math.floor(Math.min(width, height) * logoScreenPart)))
    readonly property real fitLogo: (contentBottom - height / 2 + Theme.bootLabelSize / 2 - label.implicitHeight)
                                    / (0.5 + labelGapPart / 2)
    readonly property int logoSize: Math.max(0, Math.min(wantedLogo, Math.floor(fitLogo)))
    readonly property real labelGap: logoSize * labelGapPart
    readonly property real rise: (labelGap + Theme.bootLabelSize) / 2 * textOpacity
    readonly property real labelRoom: contentBottom - label.implicitHeight - (logo.y + logo.height)
    readonly property rect hit: statusShown ? Qt.rect(0, status.y - hitSlack, width, height - stripRoom - status.y + hitSlack)
                                            : Qt.rect(0, 0, 0, 0)

    function glowAt(position) {
        const t = 1 - position
        return Qt.rgba(Theme.bootGlow.r, Theme.bootGlow.g, Theme.bootGlow.b, t * t * (3 - 2 * t))
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
            intro.start()
    }

    function restart() {
        intro.stop()
        logoOpacity = 1
        textOpacity = 0
        textFade.start()
    }

    function finish() {
        intro.stop()
        textFade.stop()
        logoOpacity = 1
        textOpacity = 1
    }

    color: Theme.screenBg
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
        NumberAnimation {
            target: root
            property: "logoOpacity"
            from: 0
            to: 1
            duration: root.logoFadeMs
        }
        PauseAnimation {
            duration: root.logoHoldMs
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

    Image {
        id: logo
        anchors.centerIn: parent
        anchors.verticalCenterOffset: -root.rise
        width: root.logoSize
        height: root.logoSize
        visible: root.logoSize > 0
        opacity: root.logoOpacity
        source: root.view.logo
        sourceSize: Qt.size(root.logoSize, root.logoSize)
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
        opacity: root.logoOpacity
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
