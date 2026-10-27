import QtQuick
import QtQuick.Controls

ProgressBar {
    property real done: 0
    property real total: 0
    property bool running: true

    indeterminate: running && total <= 0
    from: 0
    to: Math.max(total, 1)
    value: done
}
