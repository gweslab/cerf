import QtQuick
import QtQuick.Templates as T

EnterShortcut {
    required property T.Popup popup

    enabled: popup.opened
}
