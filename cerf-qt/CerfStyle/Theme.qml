pragma Singleton
import QtQuick

QtObject {
    readonly property bool dark: Application.styleHints.colorScheme === Qt.ColorScheme.Dark
    readonly property bool touchPlatform: TouchFrontend.active

    readonly property color pageBg: dark ? "#141414" : "#f0f0f0"
    readonly property color barBg: dark ? "#1c1c1c" : "#fafafa"
    readonly property color cardBg: dark ? "#1c1c1c" : "#fafafa"
    readonly property color divider: dark ? "#2f2f2f" : "#e0e0e0"
    readonly property color dim: dark ? "#808080" : "#6b6b6b"
    readonly property color warn: dark ? "#ffb900" : "#8a5a00"
    readonly property color danger: dark ? "#f48771" : "#c42b1c"
    readonly property color notice: "#e5484d"
    readonly property color noticeMark: "#ffffff"

    readonly property color screenBg: "#000000"
    readonly property color previewStopped: "#cfcfcf"
    readonly property color previewRunning: "#3fb950"
    readonly property color previewSaved: "#e8c44a"

    readonly property color overlayBar: "#cc1e1e1e"
    readonly property color overlayBarBorder: "#44ffffff"
    readonly property color overlayStrip: "#e0202020"
    readonly property color overlayIcon: "#ffffff"
    readonly property color overlayHandle: "#bbbbbb"
    readonly property color overlayActive: "#90caf9"
    readonly property color overlayLatched: "#3fb950"
    readonly property color tapBubble: "#40ffffff"
    readonly property color tapBubbleRing: "#ffffff"

    readonly property color cardHover: dark ? "#2c2c2c" : "#f5f5f5"
    readonly property color backdrop: dark ? "#99000000" : "#99303030"

    readonly property color previewBackdrop: "#1f2329"
    readonly property real previewBlurOpacity: 0.55
    readonly property color previewScrim: "#cc000000"
    readonly property color previewClear: "#00000000"
    readonly property color noFill: "#00000000"
    readonly property real previewScrimStart: 0.3
    readonly property real previewScrimEnd: 0.9
    readonly property color previewText: "#ffffff"
    readonly property color previewTextDim: "#b3ffffff"
    readonly property color previewDisc: "#73000000"
    readonly property color previewChip: "#99000000"
    readonly property color previewHover: "#59ffffff"

    function luminance(color) {
        const channel = c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
        return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b)
    }

    function readableOn(background) {
        const l = luminance(background)
        return (l + 0.05) / 0.05 >= 1.05 / (l + 0.05) ? "#000000" : "#ffffff"
    }

    function rowColumns(width, columns) {
        return width < stackedRowWidth ? 1 : columns
    }

    readonly property int captionSize: 12
    readonly property int tileTitleSize: 16
    readonly property int sectionTitleSize: 17
    readonly property int barTitleSize: 18
    readonly property int headlineSize: 21
    readonly property int displaySize: 22

    readonly property int spaceXXS: 2
    readonly property int spaceXS: 4
    readonly property int spaceS: 6
    readonly property int spaceM: 8
    readonly property int spaceL: 10
    readonly property int spaceXL: 12
    readonly property int spaceXXL: 14
    readonly property int spaceXXXL: 16
    readonly property int nestedIndent: 32
    readonly property int overlayTopGap: 40

    readonly property int radius: 5
    readonly property int previewRadius: 10
    readonly property int previewBlurRadius: 64
    readonly property int previewDiscSize: 64
    readonly property int previewGlyphSize: 48
    readonly property int deviceCellHeight: 212
    readonly property int deviceCardMinWidth: 320
    readonly property int hairline: 1
    readonly property int focusLine: 2
    readonly property int radioSize: 20
    readonly property int radioDotSize: 10
    readonly property int fieldHeight: 36
    readonly property int optionControlWidth: 250

    readonly property int compactWidth: 600
    readonly property int narrowTableWidth: 560
    readonly property int stackedRowWidth: 520

    readonly property int windowMinimumWidth: 360
    readonly property int windowMinimumHeight: 300
    readonly property int sheetWindowMinimumWidth: 560
    readonly property int sheetWindowMinimumHeight: 420
    readonly property int searchWidth: 260

    readonly property int morphMs: 180
}
