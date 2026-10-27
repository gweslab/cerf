import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page
    property bool toggleLocked: false
    readonly property bool enabledGa: sheet.guestAdditions
    readonly property var dpi: sheet.values[SheetIds.dpi]
    readonly property var fontSize: sheet.values[SheetIds.fontSize]
    readonly property var clearType: sheet.values[SheetIds.clearType]
    readonly property var colorScheme: sheet.values[SheetIds.colorScheme]
    signal bppHelp()

    function askDpi() {
        const dialog = numberPrompt.createObject(page, {
            "title": qsTr("DPI"), "maximum": PropertyOptions.ConfigIntegerMaximum(), "fields": [{"label": qsTr("DPI"), "value": sheet.DpiForPrompt(), "unit": ""}]})
        dialog.done.connect(values => sheet.SetValue(SheetIds.dpi, values[0]))
        dialog.open()
    }

    Component {
        id: numberPrompt
        NumberPromptDialog {}
    }

    SettingsGroup {
        SwitchRow {
            title: qsTr("Enable Guest Additions")
            description: qsTr("Replace the ROM's video driver with the CERF driver for a better experience. %1")
                             .arg(HtmlText.Link(ProductLinks.guestAdditionsUrl, qsTr("Learn more")))
            divider: false
            editable: page.editable && !page.toggleLocked
            checked: page.enabledGa
            onToggled: page.sheet.SetValue(SheetIds.guestAdditions, checked)
        }
    }

    ColumnLayout {
        Layout.fillWidth: true
        visible: page.enabledGa
        spacing: Theme.spaceL

        SectionLabel {
            text: qsTr("Storage")
        }
        ShareFolderRows {
            sheet: page.sheet
            editable: page.editable
        }

        SectionLabel {
            text: qsTr("Screen")
        }
        DisplayFields {
            sheet: page.sheet
            editable: page.editable
            autoDepth: page.sheet.autoDepth
            onBppHelp: page.bppHelp()
        }

        SectionLabel {
            text: qsTr("UI customizations")
        }
        SettingsGroup {
            SettingsNote {
                divider: false
                text: qsTr("Most of these properties are hacks. They work only on some Windows CE versions "
                           + "or ROMs. Change them at your own risk.")
            }
            SettingsRow {
                title: qsTr("Preset")
                description: qsTr("Optimize the settings below for a high DPI screen.")
                ChoiceBox {
                    enabled: page.editable
                    values: PropertyOptions.ScalePresetIndexes()
                    current: PropertyOptions.ScalePresetIndex(page.dpi, page.fontSize, page.clearType)
                    labelOf: i => PropertyOptions.ScalePresetLabel(i)
                    onPicked: value => page.sheet.ApplyScalePreset(value)
                }
            }
            SettingsRow {
                title: qsTr("DPI")
                description: qsTr("Override the screen density.")
                ChoiceBox {
                    enabled: page.editable
                    values: PropertyOptions.DpiChoices()
                    current: page.dpi
                    labelOf: v => PropertyOptions.DpiLabel(v)
                    allowCustom: true
                    onPicked: value => page.sheet.SetOrClear(SheetIds.dpi, value)
                    onCustomRequested: page.askDpi()
                }
            }
            SettingsRow {
                title: qsTr("Font size")
                description: qsTr("Override the system font size.")
                ChoiceBox {
                    enabled: page.editable
                    values: PropertyOptions.FontSizeChoices()
                    current: page.fontSize
                    labelOf: v => PropertyOptions.FontSizeLabel(v)
                    onPicked: value => page.sheet.SetOrClear(SheetIds.fontSize, value)
                }
            }
            SettingsRow {
                title: qsTr("ClearType")
                description: qsTr("Force font antialiasing on or off.")
                ChoiceBox {
                    enabled: page.editable
                    values: PropertyOptions.CleartypeChoices()
                    current: page.clearType
                    labelOf: v => PropertyOptions.CleartypeLabel(v)
                    onPicked: value => page.sheet.SetOrClear(SheetIds.clearType, value)
                }
            }
            SettingsRow {
                title: qsTr("Color scheme")
                description: qsTr("Colorize a grayscale device with a Windows color scheme.")
                ChoiceBox {
                    enabled: page.editable
                    values: PropertyOptions.ColorSchemeKeys()
                    current: page.colorScheme
                    labelOf: key => PropertyOptions.ColorSchemeLabel(key)
                    onPicked: value => page.sheet.SetValue(SheetIds.colorScheme, value)
                }
            }
        }

        SectionLabel {
            text: qsTr("Tweaks")
        }
        SettingsGroup {
            SwitchRow {
                title: qsTr("Allow untrusted apps")
                description: qsTr("Lets you run untrusted apps on WM. Breaks cold boot - apply only after boot!")
                divider: false
                editable: page.editable
                checked: page.sheet.allowUntrustedApps
                onToggled: page.sheet.SetValue(SheetIds.allowUntrustedApps, checked)
            }
        }
    }
}
