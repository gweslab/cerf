import QtQuick
import CerfStyle

Label {
    property bool ok: false
    property bool failed: false

    color: ok ? Theme.success : failed ? Theme.danger : Theme.dim
}
