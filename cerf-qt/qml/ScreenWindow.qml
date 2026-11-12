import QtQuick
import CerfStyle

ApplicationWindow {
    readonly property real chromeHeight: (menuBar && menuBar.visible ? menuBar.height : 0)
                                         + (footer && footer.visible ? footer.height : 0)

    color: Theme.screenBg
}
