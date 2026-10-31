#include "qt_qml_value.h"

#include <QJSValue>

QVariant PlainQmlValue(const QVariant& value) {
    if (value.metaType() == QMetaType::fromType<QJSValue>())
        return value.value<QJSValue>().toVariant(QJSValue::ConvertJSObjects);
    return value;
}
