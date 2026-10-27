import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Card {
    id: toast
    property string label: ""
    property real done: 0
    property real total: 0
    property bool spinning: false
    property bool progress: false
    readonly property int preferredWidth: 420
    readonly property int spinnerSize: 24

    padding: Theme.spaceXL
    spacing: Theme.spaceS

    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.spaceL

        BusyIndicator {
            visible: toast.spinning
            running: visible
            Layout.preferredWidth: toast.spinnerSize
            Layout.preferredHeight: toast.spinnerSize
        }
        Label {
            Layout.fillWidth: true
            text: toast.label
            elide: Text.ElideRight
        }
    }
    TransferProgress {
        Layout.fillWidth: true
        visible: toast.progress
        done: toast.done
        total: toast.total
    }
}
