import QtQuick

WarningLabel {
    required property var warning

    visible: warning.text !== ""
    text: warning.text
    danger: warning.danger
}
