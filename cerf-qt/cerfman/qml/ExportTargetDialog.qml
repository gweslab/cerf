import QtQuick
import QtQuick.Dialogs

FileDialog {
    property string name

    title: qsTr("Export %1").arg(DeviceActions.DisplayName(name))
    fileMode: FileDialog.SaveFile
    nameFilters: [qsTr("Zip archives (*.zip)")]
    defaultSuffix: "zip"
    selectedFile: DeviceExport.SuggestedTarget(name)
}
