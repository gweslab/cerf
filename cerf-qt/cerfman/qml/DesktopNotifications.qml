import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ToolBar {
    id: bar
    property int bundleUpdates: 0
    property string cerfStatus: ""
    property bool cerfAvailable: false
    readonly property bool active: bundleUpdates > 0 || cerfStatus !== ""
    signal updateBundles()
    signal openCerfUpdate()

    position: ToolBar.Footer

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.spaceM
        anchors.rightMargin: Theme.spaceM
        spacing: Theme.spaceS

        SecondaryLabel {
            visible: bar.cerfStatus !== "" && !bar.cerfAvailable
            text: bar.cerfStatus
        }
        UnreadDot {
            visible: bar.cerfAvailable
        }
        Button {
            visible: bar.cerfAvailable
            flat: true
            text: bar.cerfStatus
            onClicked: bar.openCerfUpdate()
        }
        UnreadDot {
            visible: bar.bundleUpdates > 0
        }
        Button {
            visible: bar.bundleUpdates > 0
            flat: true
            text: DeviceCards.UpdateRomsLabel(bar.bundleUpdates)
            onClicked: bar.updateBundles()
        }
        Item {
            Layout.fillWidth: true
        }
    }
}
