import QtQuick

Menu {
    id: menu
    required property Item editor
    readonly property bool editable: !editor.readOnly
    readonly property bool selection: editor.selectedText.length > 0

    MenuItem {
        text: qsTr("Undo")
        enabled: menu.editable && menu.editor.canUndo
        onTriggered: menu.editor.undo()
    }
    MenuItem {
        text: qsTr("Redo")
        enabled: menu.editable && menu.editor.canRedo
        onTriggered: menu.editor.redo()
    }
    MenuSeparator {}
    MenuItem {
        text: qsTr("Cut")
        enabled: menu.editable && menu.selection
        onTriggered: menu.editor.cut()
    }
    MenuItem {
        text: qsTr("Copy")
        enabled: menu.selection
        onTriggered: menu.editor.copy()
    }
    MenuItem {
        text: qsTr("Paste")
        enabled: menu.editable && menu.editor.canPaste
        onTriggered: menu.editor.paste()
    }
    MenuItem {
        text: qsTr("Delete")
        enabled: menu.editable && menu.selection
        onTriggered: menu.editor.remove(menu.editor.selectionStart, menu.editor.selectionEnd)
    }
    MenuSeparator {}
    MenuItem {
        text: qsTr("Select All")
        enabled: menu.editor.length > 0
        onTriggered: menu.editor.selectAll()
    }
}
