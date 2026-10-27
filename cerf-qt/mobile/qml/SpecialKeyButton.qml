import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import CerfStyle

OverlayButton {
    id: key
    property bool held: false
    property bool groupStart: false
    property real leadingInset: 0
    property string label: ""
    property string symbol: ""
    property bool holdFired: false
    property int holdMs: 0
    readonly property real dividerShare: 0.5
    readonly property real heldLineShare: 0.5
    signal keyDown()
    signal keyUp()
    signal keyCanceled()
    signal heldLong()

    Material.foreground: Theme.overlayIcon
    leftInset: leadingInset
    leftPadding: horizontalPadding + leadingInset
    icon.source: symbol !== "" ? IconSources.Icon(symbol) : ""
    text: symbol !== "" ? "" : twoLines(label)

    function twoLines(words) {
        const parts = words.split(" ")
        if (parts.length < 2)
            return words
        let split = 1
        let balance = words.length
        for (let i = 1; i < parts.length; ++i) {
            const left = parts.slice(0, i).join(" ").length
            const diff = Math.abs(left - (words.length - left - 1))
            if (diff < balance) {
                balance = diff
                split = i
            }
        }
        return parts.slice(0, split).join(" ") + "\n" + parts.slice(split).join(" ")
    }

    onPressed: {
        holdFired = false
        holdTimer.restart()
        keyDown()
    }
    onReleased: {
        holdTimer.stop()
        if (!holdFired)
            keyUp()
    }
    onCanceled: {
        holdTimer.stop()
        if (!holdFired)
            keyCanceled()
    }

    Timer {
        id: holdTimer
        interval: key.holdMs
        onTriggered: {
            key.holdFired = true
            key.heldLong()
        }
    }

    Rectangle {
        visible: key.groupStart
        anchors.left: parent.left
        anchors.leftMargin: key.leadingInset
        anchors.verticalCenter: parent.verticalCenter
        width: Theme.hairline
        height: parent.height * key.dividerShare
        color: Theme.overlayBarBorder
    }

    Rectangle {
        visible: key.held
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.horizontalCenterOffset: key.leadingInset / 2
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Theme.spaceXS
        width: (parent.width - key.leadingInset) * key.heldLineShare
        height: Theme.focusLine
        radius: height / 2
        color: Theme.overlayLatched
    }
}
