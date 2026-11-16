import QtQuick

Item {
    id: root
    property QtObject view
    property string uiFamily
    property string monoFamily
    property point pixelScale: Qt.point(1, 1)
    property var safeMargins

    readonly property bool enterprise: view.splashLogo !== ""

    BootScreenLayer {
        anchors.fill: parent
        visible: !root.enterprise
        view: root.view
        uiFamily: root.uiFamily
        monoFamily: root.monoFamily
        pixelScale: root.pixelScale
    }

    Loader {
        anchors.fill: parent
        active: root.enterprise
        sourceComponent: EnterpriseSplashLayer {
            view: root.view
            insetLeft: root.safeMargins.left
            insetBottom: root.safeMargins.bottom
        }
    }
}
