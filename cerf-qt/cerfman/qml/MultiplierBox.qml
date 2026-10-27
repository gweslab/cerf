import QtQuick

ChoiceBox {
    id: box
    required property QtObject sheet
    required property string key

    values: PropertyOptions.MultiplierChoices(key)
    current: PropertyOptions.MultiplierChoice(sheet.values[key])
    labelOf: v => PropertyOptions.MultiplierLabel(v)
    onPicked: value => sheet.SetOrClear(key, value)
}
