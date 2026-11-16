pragma Singleton
import QtQuick
import QtQuick.Controls.Material

QtObject {
    readonly property bool dark: Application.styleHints.colorScheme === Qt.ColorScheme.Dark
    readonly property bool touchPlatform: TouchFrontend.active
    readonly property int fallbackAccent: Material.Blue
    readonly property var controlAccent: SystemAccent.known ? SystemAccent.color : fallbackAccent

    readonly property color pageBg: dark ? "#141414" : "#f0f0f0"
    readonly property color barBg: dark ? "#1c1c1c" : "#fafafa"
    readonly property color windowBarBg: dark ? "#202020" : "#f0f0f0"
    readonly property color windowBarLine: dark ? "#3c3c3c" : "#c8c8c8"
    readonly property color windowBarHover: dark ? "#343434" : "#dadada"
    readonly property color cardBg: dark ? "#1c1c1c" : "#fafafa"
    readonly property color divider: dark ? "#2f2f2f" : "#e0e0e0"
    readonly property color dim: dark ? "#808080" : "#6b6b6b"
    readonly property color warn: dark ? "#ffb900" : "#8a5a00"
    readonly property color danger: dark ? "#f48771" : "#c42b1c"
    readonly property color notice: "#e5484d"
    readonly property color noticeMark: "#ffffff"

    readonly property color screenBg: "#000000"
    readonly property color canvasTabBg: dark ? "#000000" : "#f3f3f3"
    readonly property color previewStopped: "#cfcfcf"
    readonly property color previewRunning: "#3fb950"
    readonly property color previewSaved: "#e8c44a"

    readonly property color overlayBar: "#cc1e1e1e"
    readonly property color overlayBarBorder: "#44ffffff"
    readonly property color overlayStrip: "#e0202020"
    readonly property color overlayIcon: "#ffffff"
    readonly property color overlayHandle: "#bbbbbb"
    readonly property color overlayActive: SystemAccent.darkKnown ? SystemAccent.darkColor : Material.color(fallbackAccent, Material.Shade200)
    readonly property color overlayLatched: "#3fb950"
    readonly property color tapBubble: "#40ffffff"
    readonly property color tapBubbleRing: "#ffffff"

    readonly property color hudBackdrop: "#80000000"
    readonly property color hudVeil: "#1cffffff"
    readonly property color hudVeilCenter: "#28ffffff"
    readonly property color hudVeilDown: "#50ffffff"
    readonly property color hudInk: "#ececec"
    readonly property color hudArrow: "#a0a0a0"
    readonly property color hudHint: "#969696"
    readonly property color hudLatchRim: "#5aa0ff"
    readonly property color hudSeparator: "#404040"

    readonly property color cardWarning: "#f2c94c"
    readonly property color cardWarningRim: "#bf951e"
    readonly property color cardWarningText: "#1e1e1e"
    readonly property color cardError: "#cc3c3c"
    readonly property color cardErrorRim: "#962323"
    readonly property color cardErrorText: "#ffffff"
    readonly property color cardSuccess: "#388e3c"
    readonly property color cardSuccessRim: "#246428"
    readonly property color cardSuccessText: "#ffffff"
    readonly property color cardMore: "#404040"
    readonly property color cardMoreRim: "#282828"
    readonly property color cardMoreText: "#e6e6e6"
    readonly property color cardShadow: "#46000000"

    readonly property color bootGlow: dark ? "#192028" : "#dcdfe3"
    readonly property color bootLabel: dark ? "#ffffff" : "#1e1e1e"
    readonly property color bootStatus: dark ? "#969696" : "#6b6b6b"
    readonly property color consoleText: dark ? "#cdcdcd" : "#2b2b2b"
    readonly property color consoleError: dark ? "#ff6e6e" : "#c42b1c"
    readonly property color consoleWarning: dark ? "#ebd25a" : "#8a5a00"

    readonly property color barChipFill: "#282c34"
    readonly property color barOutline: "#9696a0"
    readonly property color barDiskFill: "#30343c"
    readonly property color barDiskHub: "#aaafb9"
    readonly property color barVibrate: "#c8a050"
    readonly property color barLedDark: "#222c24"
    readonly property color barLedRim: "#96a096"
    readonly property color barLedRimBlink: "#78e682"
    readonly property color barGridDark: "#3c321e"
    readonly property color barGridOutline: "#5a4b28"
    readonly property color barPowerOk: "#9ba5af"
    readonly property color barPowerOkFill: "#26303a"
    readonly property color barPowerFail: "#f56969"
    readonly property color barPowerFailFill: "#691c1c"
    readonly property color barBatteryHigh: "#4ec95a"
    readonly property color barBatteryLow: "#dcc83c"
    readonly property color barBatteryCritical: "#e55050"
    readonly property color barBatteryFrame: "#aaaab4"
    readonly property color barBatteryBody: "#1e2026"
    readonly property color barBolt: "#78dcff"
    readonly property color barBoltRim: "#283c50"
    readonly property color barFolderOn: "#e8c45c"
    readonly property color barFolderOff: "#e0e0e0"
    readonly property color barRx: "#e55050"
    readonly property color barTx: "#4ec95a"
    readonly property color barDotRim: "#141414"
    readonly property real barDisabledOpacity: 0.588235

    readonly property color cursorOutline: "#000000"
    readonly property color cursorFill: "#ffffff"

    readonly property color pausedVeil: "#000000"
    readonly property real pausedVeilOpacity: 0.349609375
    readonly property real pausedSaturation: -0.375375375

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
    readonly property color previewHover: "#59ffffff"
    readonly property real chipSaturation: 0.55
    readonly property real chipLightness: 0.3
    readonly property real chipAlpha: 0.9
    readonly property color success: "#3fb950"
    readonly property color successMark: "#ffffff"
    readonly property color accentFill: SystemAccent.known ? SystemAccent.color
                                                           : Material.color(fallbackAccent, dark ? Material.Shade200 : Material.Shade500)
    readonly property color accentTextDark: "#000000"
    readonly property color accentTextLight: "#ffffff"
    readonly property color onAccent: SystemAccent.TextOn(accentFill, accentTextDark, accentTextLight)

    function chipColor(text) {
        let hash = 0
        for (let i = 0; i < text.length; ++i)
            hash = (hash * 31 + text.charCodeAt(i)) >>> 0
        return Qt.hsla((hash % 360) / 360, chipSaturation, chipLightness, chipAlpha)
    }

    function rowColumns(width, columns) {
        return width < stackedRowWidth ? 1 : columns
    }

    function scrollBarInteractive(size) {
        return !touchPlatform && size < 1.0
    }

    readonly property int fitMinimumPixelSize: 1
    readonly property int hudHintMinimumSize: 8
    readonly property int cardFontSize: 13
    readonly property int cardCompactFontSize: 11
    readonly property int consoleFontSize: 11
    readonly property int bootLabelSize: 18
    readonly property int bootStatusSize: 12
    readonly property int captionSize: 12
    readonly property int tileTitleSize: 16
    readonly property int sectionTitleSize: 17
    readonly property int barTitleSize: 18
    readonly property int headlineSize: 21
    readonly property int displaySize: 22
    readonly property int stampSize: 34
    readonly property int stampLetterSpacing: 4

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
    readonly property int dialogSymbolSize: 32
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
    readonly property int tipDelayMs: 400
}
