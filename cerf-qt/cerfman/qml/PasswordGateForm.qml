import QtQuick
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: form
    readonly property string title: qsTr("Password - %1").arg(ProductLinks.productName)
    readonly property int logoWidth: 240

    signal passed()

    function takeFocus() {
        field.forceActiveFocus()
    }

    spacing: Theme.spaceXXXL

    Image {
        Layout.alignment: Qt.AlignHCenter
        Layout.fillWidth: true
        Layout.maximumWidth: form.logoWidth
        source: PasswordGate.LogoSource()
        sourceSize.width: form.logoWidth
        fillMode: Image.PreserveAspectFit
    }
    TextField {
        id: field
        Layout.alignment: Qt.AlignHCenter
        Layout.fillWidth: true
        Layout.maximumWidth: form.logoWidth
        echoMode: TextInput.Password
        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
        placeholderText: qsTr("Password")
        onTextEdited: {
            if (PasswordGate.Submit(text))
                form.passed()
        }
    }
}
