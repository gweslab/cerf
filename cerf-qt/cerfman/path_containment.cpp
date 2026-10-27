#include "path_containment.h"

bool PathBelow(const QString& root, const QString& candidate) { return candidate.startsWith(root + QLatin1Char('/')); }

bool PathInside(const QString& root, const QString& candidate) {
    return candidate == root || PathBelow(root, candidate);
}
