import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page
    readonly property string boardId: sheet.boardId
    readonly property var params: CpuConfigCatalog.Params(boardId)
    readonly property var overrides: sheet.cpuOverrides
    signal invalidValue(string message)

    function commitAll() {
        for (let i = 0; i < textRows.count; ++i) {
            if (!textRows.itemAt(i).commit(true))
                return false
        }
        return true
    }

    SettingsGroup {
        SettingsNote {
            divider: false
            text: qsTr("Tweaking these settings will render emulation broken. Expect crashes or wrong behaviour.")
        }
        SettingsRow {
            title: qsTr("CPU rate multiplier")
            description: qsTr("Multiply the guest CPU clock. The guest does more work in each second.")
            MultiplierBox {
                enabled: page.editable
                sheet: page.sheet
                key: SheetIds.cpuRateMultiplier
            }
        }
    }

    SettingsGroup {
        SettingsRow {
            title: qsTr("Preset")
            divider: false
            ChoiceBox {
                enabled: page.editable
                values: CpuConfigCatalog.PresetChoices(page.boardId)
                current: page.sheet.cpuPreset
                labelOf: v => CpuConfigCatalog.PresetChoiceLabel(page.boardId, v)
                onPicked: value => page.sheet.ApplyCpuPreset(value)
            }
        }
        Repeater {
            id: textRows
            model: page.params
            delegate: SettingsRow {
                id: paramRow
                required property var modelData
                readonly property bool choice: modelData.options.length > 0
                readonly property var override: page.overrides[modelData.id]

                function commit(report) {
                    if (choice)
                        return true
                    const text = field.text.trim()
                    if (text === CpuConfigCatalog.ParamValueLabel(modelData.id, modelData["default"], override))
                        return true
                    if (override === null
                            && text === CpuConfigCatalog.ValueLabel(modelData.id, modelData["default"])) {
                        field.text = Qt.binding(() => paramRow.shownText())
                        return true
                    }
                    const value = CpuConfigCatalog.ParseText(modelData.id, text)
                    if (value === undefined) {
                        if (report) {
                            page.invalidValue(CpuConfigCatalog.InvalidMessage(modelData.id))
                            field.forceActiveFocus()
                        }
                        return false
                    }
                    page.sheet.SetCpuOverride(modelData.id, value)
                    field.text = Qt.binding(() => paramRow.shownText())
                    return true
                }

                function shownText() {
                    return CpuConfigCatalog.ParamValueLabel(modelData.id, modelData["default"], override)
                }

                title: modelData.name

                Column {
                    width: parent.width

                    ChoiceBox {
                        visible: paramRow.choice
                        enabled: page.editable
                        values: paramRow.modelData.options
                        current: paramRow.override
                        labelOf: v => CpuConfigCatalog.ParamValueLabel(paramRow.modelData.id,
                                                                       paramRow.modelData["default"], v)
                        onPicked: value => page.sheet.SetCpuOverride(paramRow.modelData.id, value)
                    }

                    RowLayout {
                        visible: !paramRow.choice
                        width: parent.width
                        spacing: Theme.spaceS
                        DefaultValueField {
                            id: field
                            Layout.fillWidth: true
                            enabled: page.editable
                            readonly property bool showsAutoLabel: paramRow.override === null
                                                                   && text === paramRow.shownText()
                            text: paramRow.shownText()
                            showingDefault: showsAutoLabel && !activeFocus
                            onActiveFocusChanged: {
                                if (activeFocus && showsAutoLabel) {
                                    text = CpuConfigCatalog.ValueLabel(paramRow.modelData.id,
                                                                       paramRow.modelData["default"])
                                    selectAll()
                                } else if (!activeFocus) {
                                    paramRow.commit(false)
                                }
                            }
                            onAccepted: paramRow.commit(false)
                        }
                        Button {
                            enabled: page.editable
                            text: qsTr("Reset")
                            onClicked: {
                                page.sheet.SetCpuOverride(paramRow.modelData.id, null)
                                field.text = Qt.binding(() => paramRow.shownText())
                            }
                        }
                    }
                }
            }
        }
    }
}
