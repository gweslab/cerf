#include "sha256_text.h"

bool SameSha256(const QString& left, const QString& right) { return left.compare(right, Qt::CaseInsensitive) == 0; }
