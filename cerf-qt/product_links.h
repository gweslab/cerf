#pragma once

#include <cerfcore/core/product_name.h>
#include "product_author_text.h"

#include <cstddef>

namespace cerffrontend {

using cerfcore::kProductName;

template <size_t N>
struct LinkText {
    char text[N];
};

template <size_t A, size_t B>
constexpr LinkText<A + B - 1> JoinLink(const char (&base)[A], const char (&path)[B]) {
    LinkText<A + B - 1> out{};
    for (size_t i = 0; i + 1 < A; ++i) out.text[i] = base[i];
    for (size_t i = 0; i < B; ++i) out.text[A - 1 + i] = path[i];
    return out;
}

inline constexpr char kProductAuthor[]    = CERF_PRODUCT_AUTHOR;
inline constexpr char kProductAuthorUrl[] = "https://yaroslavkibysh.com";
inline constexpr int  kProductFirstYear   = 2019;
inline constexpr char kWebsiteUrl[]       = "https://cerf.cx";
inline constexpr char kDiscordUrl[]       = "https://discord.gg/QREE9Y2v2d";
inline constexpr char kPatreonUrl[]       = "https://www.patreon.com/dz3n";

inline constexpr auto kDownloadUrl           = JoinLink(kWebsiteUrl, "/download/");
inline constexpr auto kArticlesUrl           = JoinLink(kWebsiteUrl, "/articles/");
inline constexpr auto kGuestAdditionsUrl     = JoinLink(kArticlesUrl.text, "guest-additions/");
inline constexpr auto kBundleRepositoriesUrl = JoinLink(kArticlesUrl.text, "bundle-repositories/");
inline constexpr auto kHibernationWarningUrl = JoinLink(kWebsiteUrl, "/hibernation-warning");
inline constexpr auto kFeedbackUrl           = JoinLink(kWebsiteUrl, "/feedback");

inline constexpr char kGitHubUrl[]          = "https://github.com/";
inline constexpr char kGitHubApiUrl[]       = "https://api.github.com/";
inline constexpr char kGitHubApiMediaType[] = "application/vnd.github+json";
inline constexpr char kRepository[]         = "gweslab/cerf";

inline constexpr auto kRepositoryUrl       = JoinLink(kGitHubUrl, kRepository);
inline constexpr auto kLatestReleaseUrl    = JoinLink(kRepositoryUrl.text, "/releases/latest");
inline constexpr auto kCiRunsUrl           = JoinLink(kRepositoryUrl.text, "/actions");
inline constexpr auto kRepositoryApiUrl    = JoinLink(JoinLink(kGitHubApiUrl, "repos/").text, kRepository);
inline constexpr auto kStableReleaseApiUrl = JoinLink(kRepositoryApiUrl.text, "/releases/latest");
inline constexpr auto kOpenIssuesApiUrl =
    JoinLink(JoinLink(JoinLink(kGitHubApiUrl, "search/issues?q=repo:").text, kRepository).text,
             "+is:issue+is:open&sort=reactions&order=desc&per_page=100");

}
