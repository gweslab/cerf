import QtQuick
import QtQuick.Controls

PageFooter {
    id: footer
    property bool mobile: false
    property string actionName: ""
    property bool actionEnabled: true
    signal back()
    signal action()
    signal cancel()

    Button {
        visible: !footer.mobile
        text: qsTr("Back")
        onClicked: footer.back()
    }
    Button {
        visible: !footer.mobile
        text: footer.actionName
        highlighted: true
        enabled: footer.actionEnabled
        onClicked: footer.action()
    }
    Button {
        visible: !footer.mobile
        text: qsTr("Cancel")
        onClicked: footer.cancel()
    }
}
