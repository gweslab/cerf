import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

OkCancelDialog {
    id: dialog
    property var fields: []
    property int minimum: 1
    required property real maximum
    property string error: ""
    property alias tools: toolRow.data
    readonly property int fieldWidth: 110
    signal done(var values)

    function valueAt(index) {
        const text = inputs.itemAt(index).text.trim()
        return text === "" ? 0 : parseInt(text, 10)
    }

    function setValues(values) {
        values.forEach((value, index) => inputs.itemAt(index).text = String(value))
        error = ""
    }

    function submit() {
        const values = []
        for (let i = 0; i < inputs.count; ++i) {
            const value = valueAt(i)
            if (value < minimum || value > maximum) {
                error = qsTr("Enter a whole number from %1 to %2.").arg(minimum).arg(String(maximum))
                return
            }
            values.push(value)
        }
        done(values)
        close()
    }

    preferredWidth: 320

    onOpened: inputs.itemAt(0).forceActiveFocus()
    onOk: submit()
    onClosed: destroy()

    ColumnLayout {
        width: dialog.availableWidth
        spacing: Theme.spaceL

        GridLayout {
            Layout.fillWidth: true
            columns: 3
            columnSpacing: Theme.spaceXL
            rowSpacing: Theme.spaceS

            Repeater {
                id: inputs
                model: dialog.fields
                delegate: TextField {
                    required property var modelData
                    required property int index
                    Layout.row: index
                    Layout.column: 1
                    Layout.preferredWidth: dialog.fieldWidth
                    text: String(modelData.value)
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: RegularExpressionValidator { regularExpression: /[0-9]*/ }
                    onAccepted: dialog.submit()
                    Component.onCompleted: if (index === 0) selectAll()
                }
            }
            Repeater {
                model: dialog.fields
                delegate: Label {
                    required property var modelData
                    required property int index
                    Layout.row: index
                    Layout.column: 0
                    text: modelData.label
                }
            }
            Repeater {
                model: dialog.fields
                delegate: Label {
                    required property var modelData
                    required property int index
                    Layout.row: index
                    Layout.column: 2
                    text: modelData.unit
                }
            }
        }

        WarningLabel {
            Layout.fillWidth: true
            visible: dialog.error !== ""
            text: dialog.error
            danger: true
        }

        Flow {
            id: toolRow
            Layout.fillWidth: true
            visible: children.length > 0
            spacing: Theme.spaceS
        }
    }
}
