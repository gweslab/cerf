import QtQuick
import QtQuick.Dialogs
import QtQuick.Layouts
import CerfStyle

WizardPage {
    id: page
    property var chosen: []
    property var openFolders: ({})
    property var tree: ({"dirs": {}, "presets": []})
    readonly property var chosenSet: {
        const set = {}
        for (const path of chosen)
            set[path] = true
        return set
    }
    signal toggled(string path, bool on)

    title: qsTr("Manage shaders")
    searchable: true
    onSearchTextChanged: page.refill()
    filters: [
        ColumnLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceS

            Flow {
                Layout.fillWidth: true
                spacing: Theme.spaceM

                Button {
                    enabled: !ManagerOperations.busy
                    text: qsTr("Import .zip…")
                    onClicked: archiveDialog.open()
                }
                Button {
                    visible: ShaderImport.folderImport
                    enabled: !ManagerOperations.busy
                    text: qsTr("Import folder…")
                    onClicked: folderDialog.open()
                }
            }
            SecondaryLabel {
                Layout.fillWidth: true
                visible: ManagerOperations.busy
                text: ManagerOperations.label
                elide: Text.ElideRight
            }
            ProgressBar {
                Layout.fillWidth: true
                visible: ManagerOperations.busy
                indeterminate: !ManagerOperations.progressShown || ManagerOperations.total <= 0
                value: ManagerOperations.total > 0 ? ManagerOperations.done / ManagerOperations.total : 0
            }
        }
    ]

    function folderTree() {
        const root = {"dirs": {}, "presets": []}
        for (const preset of ShaderCatalog.Presets()) {
            let node = root
            for (const part of preset.path.split("/").slice(0, -1)) {
                if (node.dirs[part] === undefined)
                    node.dirs[part] = {"dirs": {}, "presets": []}
                node = node.dirs[part]
            }
            node.presets.push(preset)
        }
        return root
    }

    function matches(preset, query) {
        return query === "" || preset.path.toLowerCase().includes(query)
    }

    function count(node, query) {
        let total = node.presets.filter(p => matches(p, query)).length
        for (const name in node.dirs)
            total += count(node.dirs[name], query)
        return total
    }

    function walk(node, prefix, depth, query, out) {
        const names = Object.keys(node.dirs).sort((a, b) => a.localeCompare(b, undefined, {"sensitivity": "base"}))
        for (const name of names) {
            const path = prefix === "" ? name : prefix + "/" + name
            const total = count(node.dirs[name], query)
            if (total === 0)
                continue
            const open = query !== "" || openFolders[path] === true
            out.push({"key": "folder:" + path, "folder": true, "path": path, "name": name, "depth": depth,
                      "count": total, "open": open})
            if (open)
                walk(node.dirs[name], path, depth + 1, query, out)
        }
        for (const preset of node.presets) {
            if (matches(preset, query))
                out.push({"key": "preset:" + preset.path, "folder": false, "path": preset.path, "name": preset.name,
                          "depth": depth, "count": 0, "open": false})
        }
    }

    function refill() {
        const flat = []
        walk(tree, "", 0, searchText.toLowerCase(), flat)
        rows.apply(flat)
    }

    function toggleFolder(path) {
        const next = Object.assign({}, openFolders)
        next[path] = !next[path]
        openFolders = next
        refill()
    }

    Component.onCompleted: {
        tree = folderTree()
        refill()
    }

    Connections {
        target: ShaderCatalog
        function onRevisionChanged() {
            page.tree = page.folderTree()
            page.refill()
        }
    }

    FileDialog {
        id: archiveDialog
        title: qsTr("Import a shader archive")
        nameFilters: [qsTr("Zip archives (*.zip)")]
        onAccepted: ShaderImport.ImportArchive(selectedFile)
    }

    FolderDialog {
        id: folderDialog
        title: qsTr("Import a shader folder")
        onAccepted: ShaderImport.ImportFolder(selectedFolder)
    }

    KeyedListModel {
        id: rows
    }

    TableListView {
        anchors.fill: parent
        model: rows

        delegate: Loader {
            id: slot
            required property bool folder
            required property string path
            required property string name
            required property int depth
            required property int count
            required property bool open
            width: ListView.view.width
            sourceComponent: slot.folder ? folderRow : presetRow

            Component {
                id: folderRow
                RowDelegate {
                    leftPadding: Theme.spaceL + slot.depth * Theme.spaceXXXL
                    columns: 3
                    onClicked: page.toggleFolder(slot.path)

                    SymbolIcon {
                        name: "chevron_right"
                        color: Theme.dim
                        rotation: slot.open ? 90 : 0
                    }
                    StrongLabel {
                        Layout.fillWidth: true
                        text: slot.name
                        wrapMode: Text.Wrap
                    }
                    CaptionLabel {
                        text: slot.count === 1 ? qsTr("1 preset") : qsTr("%n presets", "", slot.count)
                    }
                }
            }

            Component {
                id: presetRow
                RowDelegate {
                    id: presetItem
                    readonly property bool chosen: page.chosenSet[slot.path] === true
                    leftPadding: Theme.spaceL + slot.depth * Theme.spaceXXXL
                    columns: 2
                    onClicked: page.toggled(slot.path, !presetItem.chosen)

                    RowCheckBox {
                        checked: presetItem.chosen
                        onClicked: page.toggled(slot.path, !presetItem.chosen)
                    }
                    Label {
                        Layout.fillWidth: true
                        text: slot.name
                        wrapMode: Text.Wrap
                    }
                }
            }
        }
    }
}
