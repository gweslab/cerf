#include "path_removal.h"

#include <vector>

namespace fs = std::filesystem;

namespace {

void AllowWrite(const fs::path& path, const fs::file_status& status) {
    if ((status.permissions() & fs::perms::owner_write) != fs::perms::none) return;
    const bool       plain = fs::is_regular_file(status) || fs::is_directory(status);
    fs::perm_options mode  = fs::perm_options::add;
    if (!plain) mode |= fs::perm_options::nofollow;
    std::error_code reported_by_remove;
    fs::permissions(path, fs::perms::owner_write, mode, reported_by_remove);
}

}

std::error_code RemovePathTree(const fs::path& path) {
    std::error_code       ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (status.type() == fs::file_type::not_found) return {};
    if (ec) return ec;
    AllowWrite(path, status);
    if (fs::is_directory(status)) {
        std::vector<fs::path> children;
        for (fs::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) children.push_back(it->path());
        if (ec) return ec;
        for (const fs::path& child : children)
            if (const std::error_code failure = RemovePathTree(child)) return failure;
    }
    fs::remove(path, ec);
    return ec;
}
