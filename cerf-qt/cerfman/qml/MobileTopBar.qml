import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ToolBar {
    id: bar
    property alias query: search.text
    property int bundleUpdates: 0
    property string cerfStatus: ""
    property bool cerfAvailable: false
    readonly property bool pending: bundleUpdates > 0 || cerfAvailable
    signal updateBundles()
    signal openCerfUpdate()

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.spaceXL
        anchors.rightMargin: Theme.spaceXS

        SearchBox {
            id: search
            Layout.fillWidth: true
        }
        NotificationButton {
            id: bell
            pending: bar.pending
            onClicked: notices.popup(bell, bell.width - notices.width, bell.height)

            Menu {
                id: notices

                NoticeMenuItem {
                    visible: bar.cerfStatus !== ""
                    enabled: bar.cerfAvailable
                    unread: bar.cerfAvailable
                    text: bar.cerfStatus
                    onTriggered: bar.openCerfUpdate()
                }
                NoticeMenuItem {
                    visible: bar.bundleUpdates > 0
                    unread: true
                    text: DeviceCards.UpdateRomsLabel(bar.bundleUpdates)
                    onTriggered: bar.updateBundles()
                }
                MenuItem {
                    visible: bar.cerfStatus === "" && bar.bundleUpdates <= 0
                    enabled: false
                    text: qsTr("No notifications")
                }
            }
        }
    }
}
