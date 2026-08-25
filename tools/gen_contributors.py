import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANUAL_LIST = os.path.join(REPO_ROOT, "cerf", "host", "contributors.txt")
GENERATED_LIST = os.path.join(REPO_ROOT, "cerf", "host",
                              "contributors_generated.txt")

OWNER_NAMES = {"yaroslav kibysh"}
AI_COAUTHOR_DOMAINS = {"anthropic.com"}
EXCLUDED_LOGINS = {"dz333n", "claude"}

GRAPHQL_BATCH = 50


def git_lines(args):
    proc = subprocess.run(["git", "-C", REPO_ROOT] + args,
                          stdout=subprocess.PIPE, check=True)
    text = proc.stdout.decode("utf-8", "replace")
    return [line for line in text.splitlines() if line.strip()]


def sanitize(name):
    return "".join(c for c in name if c >= " " and c != "\x7f").strip()


def split_identity(line):
    name, sep, rest = line.partition("<")
    email = rest.partition(">")[0] if sep else ""
    return sanitize(name), email.strip().lower()


def is_excluded_identity(name, email):
    if name.lower() in OWNER_NAMES:
        return True
    return email.rpartition("@")[2] in AI_COAUTHOR_DOMAINS


def git_identities():
    found = {}

    def offer(name, email, sha):
        if name and email and not is_excluded_identity(name, email):
            found.setdefault(email, (name, sha))

    for line in git_lines(["log", "--format=%H\x1f%aN <%aE>"]):
        sha, _, who = line.partition("\x1f")
        name, email = split_identity(who)
        offer(name, email, sha)

    trailers = "%(trailers:key=Co-Authored-By,valueonly,separator=%x1E)"
    for line in git_lines(["log", "--format=%H\x1f" + trailers]):
        sha, _, rest = line.partition("\x1f")
        for value in rest.split("\x1e"):
            if value.strip():
                name, email = split_identity(value)
                offer(name, email, sha)

    return found


def repo_slug():
    url = git_lines(["remote", "get-url", "origin"])[0].strip()
    match = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?$", url)
    if not match:
        raise RuntimeError("cannot parse the origin remote: " + url)
    return match.group(1), match.group(2)


def graphql(query):
    proc = subprocess.run(["gh", "api", "graphql", "-f", "query=" + query],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    body = json.loads(proc.stdout.decode("utf-8", "replace"))
    if body.get("errors"):
        raise RuntimeError(json.dumps(body["errors"]))
    return body["data"]["repository"]


def resolve_logins(identities):
    owner, name = repo_slug()
    shas = sorted({sha for _, sha in identities.values()})
    logins = {}

    for start in range(0, len(shas), GRAPHQL_BATCH):
        chunk = shas[start:start + GRAPHQL_BATCH]
        fields = "\n".join(
            'c%d: object(oid: "%s") { ... on Commit { authors(first: 30) '
            '{ nodes { email user { login } } } } }' % (index, sha)
            for index, sha in enumerate(chunk))
        data = graphql('{ repository(owner: "%s", name: "%s") {\n%s\n} }'
                       % (owner, name, fields))
        for node in data.values():
            if not node:
                continue
            for author in node["authors"]["nodes"]:
                user = author.get("user")
                if user:
                    logins[(author.get("email") or "").lower()] = user["login"]

    return logins


def git_contributors():
    identities = git_identities()
    logins = resolve_logins(identities)

    names = []
    unresolved = []
    for email, (name, _) in identities.items():
        login = logins.get(email)
        if login is None:
            unresolved.append(name)
            names.append(name)
        elif login.lower() not in EXCLUDED_LOGINS:
            names.append(login)

    if unresolved:
        sys.stderr.write("no GitHub account for: " + ", ".join(unresolved) +
                         " (using the git name)\n")
    return names


def manual_contributors():
    names = []
    with open(MANUAL_LIST, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                name = sanitize(line)
                if name:
                    names.append(name)
    return names


def merge(*groups):
    unique = {}
    for group in groups:
        for name in group:
            unique.setdefault(name.casefold(), name)
    return sorted(unique.values(), key=lambda n: (n.casefold(), n))


def main():
    parser = argparse.ArgumentParser(
        description="Merge cerf/host/contributors.txt with the GitHub logins "
                    "of every git author and Co-Authored-By trailer, then "
                    "write cerf/host/contributors_generated.txt, which cerf.rc "
                    "embeds as the ABOUT_CONTRIBUTORS resource. Needs an "
                    "authenticated gh.")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the generated list is stale "
                             "instead of rewriting it")
    args = parser.parse_args()

    try:
        from_git = git_contributors()
    except (RuntimeError, OSError) as err:
        sys.stderr.write("GitHub login lookup failed: %s\n" % err)
        sys.stderr.write("%s left unchanged\n" % GENERATED_LIST)
        return 1

    names = merge(manual_contributors(), from_git)
    text = "".join(name + "\n" for name in names)

    existing = None
    if os.path.exists(GENERATED_LIST):
        with open(GENERATED_LIST, "r", encoding="utf-8") as handle:
            existing = handle.read()

    if args.check:
        if existing != text:
            sys.stderr.write("stale: " + GENERATED_LIST + "\n")
            return 1
        return 0

    if existing != text:
        with open(GENERATED_LIST, "w", encoding="utf-8", newline="\n") as h:
            h.write(text)

    sys.stdout.write("{} contributors ({} from GitHub): {}\n".format(
        len(names), len(set(n.casefold() for n in from_git)), ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
