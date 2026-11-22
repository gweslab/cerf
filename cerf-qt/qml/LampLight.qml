import QtQuick
import CerfStyle

Item {
    id: root
    property var lamps: []
    property double now: 0

    readonly property bool lit: lamps.some(lamp => shownColor(lamp, now) !== null)
    readonly property color color: fill(now)

    function shownColor(lamp, t) {
        if (!lamp.lit)
            return null
        const cycle = lamp.onMs + lamp.offMs
        if (!lamp.blinking || cycle === 0 || t % cycle < lamp.onMs)
            return lamp.color
        return lamp.between !== undefined ? lamp.between : null
    }

    function fill(t) {
        const main = lamps.length > 0 ? shownColor(lamps[0], t) : null
        let mixed = main !== null ? main : Theme.lampDark
        for (let i = 1; i < lamps.length; ++i) {
            const other = shownColor(lamps[i], t)
            if (other === null)
                continue
            mixed = main !== null ? Qt.rgba(Math.min(1, mixed.r + other.r), Math.min(1, mixed.g + other.g),
                                            Math.min(1, mixed.b + other.b), 1) : other
        }
        return mixed
    }

    function untilEdge(t) {
        let wait = 0
        for (const lamp of lamps) {
            const cycle = lamp.onMs + lamp.offMs
            if (!lamp.lit || !lamp.blinking || cycle === 0)
                continue
            const phase = t % cycle
            const left = phase < lamp.onMs ? lamp.onMs - phase : cycle - phase
            wait = wait === 0 ? left : Math.min(wait, left)
        }
        return wait
    }

    function followBlink() {
        now = Date.now()
        const wait = untilEdge(now)
        if (wait > 0) {
            blink.interval = wait
            blink.restart()
        } else {
            blink.stop()
        }
    }

    onLampsChanged: followBlink()
    Component.onCompleted: followBlink()

    Timer {
        id: blink
        onTriggered: root.followBlink()
    }
}
