import QtQuick
import QtQuick.Layouts
import CerfStyle

FixedWidthWindow {
    id: alert
    property string message
    property string level
    property bool topmost: false
    signal finished(var result)

    modal: true
    flags: Qt.Dialog | (topmost ? Qt.WindowStaysOnTopHint : 0)
    contentHeight: column.implicitHeight

    onClosing: alert.finished(undefined)

    Shortcut {
        sequence: "Escape"
        onActivated: alert.close()
    }
    EnterShortcut {
        onActivated: alert.close()
    }

    ColumnLayout {
        id: column
        width: alert.width
        spacing: 0

        SymbolMessage {
            Layout.fillWidth: true
            Layout.margins: Theme.spaceXXL
            text: alert.message
            level: alert.level
        }
        PageFooter {
            Layout.fillWidth: true

            Button {
                text: qsTr("OK")
                highlighted: true
                onClicked: alert.close()
            }
        }
    }
}
