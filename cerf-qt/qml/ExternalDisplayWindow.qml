import QtQuick
import CerfStyle
import Cerfman

ScreenWindow {
    id: root
    property QtObject display: null
    property bool chromeShown: true
    property alias view: view

    menuBar: Loader {
        active: !NativeMenuBar.active
        visible: active && root.chromeShown
        sourceComponent: HostMenuBar {
            titles: root.display.MenuTitles()
            contentFor: (index, menu) => root.display.Menu(index, menu)
            onPicked: (menu, id) => root.display.MenuPicked(menu, id)
        }
    }

    ExternalDisplayView {
        id: view
        anchors.fill: parent
        fillColor: Theme.screenBg
        focus: true
    }

    function askEject() {
        const yes = qsTr("Yes")
        const dialog = Qt.createComponent("FlowDialog.qml").createObject(root.contentItem, {
            "title": root.title,
            "message": qsTr("Eject VGA card?"),
            "buttons": [yes, qsTr("No")]
        })
        dialog.choice.connect(choice => {
            if (choice === yes)
                root.display.Eject()
        })
        dialog.open()
    }
}
