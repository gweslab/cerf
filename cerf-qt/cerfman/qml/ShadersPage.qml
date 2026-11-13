import QtQuick
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page
    readonly property string presetsKey: JSON.stringify(sheet.shaderPresets)
    readonly property var presets: JSON.parse(presetsKey)
    readonly property var values: sheet.shaderParameters
    property var expanded: ({})
    signal manage()

    function save(nextPresets, nextValues, screenshots) {
        sheet.SetShaders(nextPresets, nextValues, screenshots)
    }

    function setPreset(path, on) {
        const index = presets.findIndex(p => p.path === path)
        if (on && index < 0)
            save(presets.concat([{"path": path, "enabled": true}]), values, sheet.shaderScreenshots)
        else if (!on && index >= 0)
            remove(index)
    }

    function setEnabled(index, on) {
        const next = presets.slice()
        next[index] = {"path": next[index].path, "enabled": on}
        save(next, values, sheet.shaderScreenshots)
    }

    function move(index, delta) {
        const next = presets.slice()
        const moved = next.splice(index, 1)[0]
        next.splice(index + delta, 0, moved)
        save(next, values, sheet.shaderScreenshots)
    }

    function remove(index) {
        const next = presets.slice()
        next.splice(index, 1)
        const declared = {}
        for (const preset of next) {
            for (const parameter of ShaderCatalog.Inspect([preset.path]).parameters)
                declared[parameter.name] = true
        }
        const kept = {}
        for (const name in values) {
            if (declared[name])
                kept[name] = values[name]
        }
        save(next, kept, sheet.shaderScreenshots)
    }

    function setParameter(parameter, value) {
        const next = Object.assign({}, values)
        if (Math.abs(value - parameter.initial) < 1e-6)
            delete next[parameter.name]
        else
            next[parameter.name] = value
        save(presets, next, sheet.shaderScreenshots)
    }

    function toggleExpanded(path) {
        const next = Object.assign({}, expanded)
        next[path] = !next[path]
        expanded = next
    }

    component Expander: ToolButton {
        property bool open: false
        icon.source: IconSources.Icon("chevron_right")
        rotation: open ? 90 : 0
    }

    function valueText(value, step) {
        const decimals = step > 0 && step < 1 ? Math.min(4, Math.ceil(-Math.log10(step) - 1e-9)) : 0
        return Number(value).toFixed(decimals)
    }

    SectionLabel {
        text: HtmlText.Link(ProductLinks.librashaderUrl, "librashader")
    }

    SettingsGroup {
        SwitchRow {
            title: qsTr("Shaders on screenshots")
            description: qsTr("Save and copy screenshots as the screen shows them.")
            divider: false
            editable: page.editable
            checked: page.sheet.shaderScreenshots
            onToggled: page.save(page.presets, page.values, checked)
        }
        SettingsRow {
            title: qsTr("Manage shaders")
            description: qsTr("Pick the shaders that this device lists, or import new shaders.")
            wideControl: false
            Button {
                enabled: page.editable
                text: qsTr("Manage…")
                onClicked: page.manage()
            }
        }
        SettingsRow {
            title: qsTr("Download RetroArch shaders")
            wideControl: false
            Button {
                text: qsTr("Open")
                onClicked: DesktopShell.OpenLink(ProductLinks.slangShadersUrl)
            }
        }
    }

    SectionLabel {
        visible: page.presets.length > 0
        text: qsTr("Active shaders")
    }

    SettingsGroup {
        visible: page.presets.length > 0

        Repeater {
            model: page.presets
            delegate: ColumnLayout {
                id: entry
                required property var modelData
                required property int index
                readonly property string path: modelData.path
                readonly property bool open: page.expanded[path] === true
                readonly property var inspected: open ? ShaderCatalog.Inspect([path]) : ({"parameters": [], "error": ""})
                Layout.fillWidth: true
                spacing: 0

                SettingsItem {
                    divider: entry.index > 0
                    GridLayout {
                        id: head
                        readonly property bool stacked: Theme.rowColumns(width, 2) === 1
                        Layout.fillWidth: true
                        columns: stacked ? 1 : 2
                        columnSpacing: Theme.spaceM
                        rowSpacing: 0

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.spaceM

                            Switch {
                                enabled: page.editable
                                checked: entry.modelData.enabled
                                onToggled: page.setEnabled(entry.index, checked)
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: Theme.spaceXXS

                                Label {
                                    Layout.fillWidth: true
                                    text: entry.path.split("/").pop().replace(/\.slangp$/, "")
                                    wrapMode: Text.Wrap
                                }
                                CaptionLabel {
                                    Layout.fillWidth: true
                                    text: entry.path.split("/").slice(0, -1).join("/")
                                    wrapMode: Text.Wrap
                                }
                                TapHandler {
                                    onTapped: page.toggleExpanded(entry.path)
                                }
                            }
                            Expander {
                                visible: head.stacked
                                open: entry.open
                                onClicked: page.toggleExpanded(entry.path)
                            }
                        }
                        RowLayout {
                            Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                            spacing: Theme.spaceXS

                            ToolButton {
                                enabled: page.editable && entry.index > 0
                                icon.source: IconSources.Icon("arrow_upward")
                                onClicked: page.move(entry.index, -1)
                            }
                            ToolButton {
                                enabled: page.editable && entry.index < page.presets.length - 1
                                icon.source: IconSources.Icon("arrow_downward")
                                onClicked: page.move(entry.index, 1)
                            }
                            Button {
                                enabled: page.editable
                                text: qsTr("Remove")
                                onClicked: page.remove(entry.index)
                            }
                            Expander {
                                visible: !head.stacked
                                open: entry.open
                                onClicked: page.toggleExpanded(entry.path)
                            }
                        }
                    }
                }

                SettingsNote {
                    visible: entry.open && entry.inspected.error !== ""
                    text: entry.inspected.error
                }
                Repeater {
                    model: entry.inspected.parameters
                    delegate: SettingsRow {
                        id: parameterRow
                        required property var modelData
                        readonly property bool adjustable: modelData.minimum < modelData.maximum
                        readonly property bool changed: page.values[modelData.name] !== undefined
                        readonly property real current: changed ? page.values[modelData.name] : modelData.initial
                        title: modelData.description !== "" ? modelData.description : modelData.name
                        RowLayout {
                            visible: parameterRow.adjustable
                            width: parent.width
                            spacing: Theme.spaceS
                            Slider {
                                Layout.fillWidth: true
                                enabled: page.editable
                                from: parameterRow.modelData.minimum
                                to: parameterRow.modelData.maximum
                                stepSize: parameterRow.modelData.step
                                snapMode: Slider.SnapAlways
                                value: parameterRow.current
                                onMoved: page.setParameter(parameterRow.modelData, value)
                            }
                            Label {
                                text: page.valueText(parameterRow.current, parameterRow.modelData.step)
                            }
                            Button {
                                enabled: page.editable && parameterRow.changed
                                text: qsTr("Reset")
                                onClicked: page.setParameter(parameterRow.modelData, parameterRow.modelData.initial)
                            }
                        }
                    }
                }
            }
        }
    }
}
