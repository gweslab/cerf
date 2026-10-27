import QtQuick
import QtQuick.Controls
import CerfStyle

PageFooter {
    id: footer
    property bool acceptEnabled: true
    property string warning: ""
    signal accept()
    signal reject()

    WarningLabel {
        visible: footer.warning !== ""
        text: footer.warning
        wrapMode: Text.NoWrap
    }
    Button {
        text: qsTr("OK")
        highlighted: true
        enabled: footer.acceptEnabled
        onClicked: footer.accept()
    }
    Button {
        text: qsTr("Cancel")
        onClicked: footer.reject()
    }
}
