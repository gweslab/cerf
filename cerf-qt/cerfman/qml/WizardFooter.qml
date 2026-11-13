import QtQuick
import CerfStyle

PageFooter {
    id: footer
    property bool mobile: false
    property string actionName: ""
    property bool actionEnabled: true
    property bool backShown: true
    signal back()
    signal action()
    signal cancel()

    Button {
        visible: !footer.mobile && footer.backShown
        text: qsTr("Back")
        onClicked: footer.back()
    }
    Button {
        visible: !footer.mobile && footer.actionName !== ""
        text: footer.actionName
        highlighted: true
        enabled: footer.actionEnabled
        onClicked: footer.action()
    }
    Button {
        visible: !footer.mobile
        text: footer.actionName !== "" ? qsTr("Cancel") : qsTr("Close")
        onClicked: footer.cancel()
    }
}
