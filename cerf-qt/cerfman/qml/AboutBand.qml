import QtQuick
import QtQuick.Layouts

Image {
    Layout.fillWidth: true
    Layout.preferredHeight: width * AboutModel.bandAspect
    source: IconSources.aboutBand
    sourceSize.width: width
    sourceSize.height: height
    asynchronous: true
}
