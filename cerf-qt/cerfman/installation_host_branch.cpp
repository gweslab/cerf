#include "installation_host_branch.h"

#include "host_branch_table.h"

#include <algorithm>
#include <iterator>

namespace {

const host_branch_table::Row& RowOf(const QString& host_branch) {
    return *std::find_if(std::begin(host_branch_table::kRows), std::end(host_branch_table::kRows),
                         [&](const host_branch_table::Row& row) { return host_branch == QLatin1String(row.name); });
}

}

QString ReleaseMarker(const QString& host_branch) {
    return QLatin1String(host_branch_table::kReleasePrefix) + QLatin1String(RowOf(host_branch).platform_dir);
}
