import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

SheetGroup {
    id: group
    property int autoDepth: 0
    signal bppHelp()

    function askResolution() {
        const size = sheet.ResolutionForPrompt()
        const dialog = resolutionPrompt.createObject(group, {
            "title": qsTr("Display resolution"),
            "maximum": PropertyOptions.ConfigIntegerMaximum(),
            "fields": [{"label": qsTr("Width"), "value": size[0], "unit": "px"},
                       {"label": qsTr("Height"), "value": size[1], "unit": "px"}]})
        dialog.done.connect(values => sheet.SetResolution(values))
        dialog.open()
    }

    Component {
        id: resolutionPrompt
        ResolutionPromptDialog {}
    }

    SettingsRow {
        title: qsTr("Display resolution")
        divider: false
        ChoiceBox {
            enabled: group.editable
            values: PropertyOptions.ResolutionChoices()
            current: group.sheet.resolution
            labelOf: v => PropertyOptions.ResolutionChoiceLabel(v, group.sheet.autoSize)
            allowCustom: true
            onPicked: value => group.sheet.SetResolution(value)
            onCustomRequested: group.askResolution()
        }
    }
    SettingsRow {
        title: qsTr("Color depth")
        description: qsTr("A wrong value breaks the guest. %1").arg(HtmlText.Link("help", qsTr("Learn more")))
        onAnchorActivated: group.bppHelp()
        ChoiceBox {
            enabled: group.editable
            values: PropertyOptions.BppChoices()
            current: group.sheet.values[SheetIds.bpp]
            labelOf: v => PropertyOptions.BppLabel(v, group.autoDepth)
            onPicked: value => group.sheet.SetOrClear(SheetIds.bpp, value)
        }
    }
}
