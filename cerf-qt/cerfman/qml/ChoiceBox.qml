import QtQuick
import QtQuick.Controls

ComboBox {
    id: box
    property var values: []
    property var current: null
    property var labelOf: value => String(value)
    property bool allowCustom: false
    signal picked(var value)
    signal customRequested()

    function same(a, b) {
        return JSON.stringify(a) === JSON.stringify(b)
    }

    width: parent ? parent.width : implicitWidth
    model: values.map(v => labelOf(v)).concat(allowCustom ? [PropertyOptions.customChoice] : [])
    displayText: labelOf(current)
    currentIndex: values.findIndex(v => same(v, current))

    onActivated: index => {
        if (index < values.length) {
            if (!same(values[index], current))
                picked(values[index])
        } else {
            customRequested()
        }
        currentIndex = Qt.binding(() => values.findIndex(v => same(v, current)))
    }
}
