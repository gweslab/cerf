import QtQuick
import CerfStyle

Label {
    property bool danger: false

    color: danger ? Theme.danger : Theme.warn
    wrapMode: Text.Wrap
}
