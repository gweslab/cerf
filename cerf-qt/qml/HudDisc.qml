import QtQuick
import QtQuick.Shapes
import CerfStyle

Shape {
    id: disc
    property alias gradient: path.fillGradient
    preferredRendererType: Shape.CurveRenderer
    ShapePath {
        id: path
        strokeColor: Theme.noFill
        PathAngleArc {
            centerX: disc.width / 2
            centerY: disc.height / 2
            radiusX: disc.width / 2
            radiusY: disc.height / 2
            startAngle: 0
            sweepAngle: 360
        }
    }
}
