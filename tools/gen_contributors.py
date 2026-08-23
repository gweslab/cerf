import argparse
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANUAL_LIST = os.path.join(REPO_ROOT, "cerf", "host", "contributors.txt")
GENERATED_LIST = os.path.join(REPO_ROOT, "cerf", "host",
                              "contributors_generated.txt")

OWNER_NAMES = {"yaroslav kibysh"}
AI_COAUTHOR_DOMAINS = {"anthropic.com"}


def git_lines(args):
    proc = subprocess.run(["git", "-C", REPO_ROOT] + args,
                          stdout=subprocess.PIPE, check=True)
    text = proc.stdout.decode("utf-8", "replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def sanitize(name):
    return "".join(c for c in name if c >= " " and c != "\x7f").strip()


def split_identity(line):
    name, sep, rest = line.partition("<")
    email = rest.partition(">")[0] if sep else ""
    return sanitize(name), email.strip().lower()


def is_excluded(name, email):
    if name.lower() in OWNER_NAMES:
        return True
    return email.rpartition("@")[2] in AI_COAUTHOR_DOMAINS


def git_contributors():
    names = []
    formats = ["%aN <%aE>", "%(trailers:key=Co-Authored-By,valueonly)"]
    for fmt in formats:
        for line in git_lines(["log", "--format=" + fmt]):
            name, email = split_identity(line)
            if name and not is_excluded(name, email):
                names.append(name)
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
        description="Merge cerf/host/contributors.txt with the distinct git "
                    "authors and Co-Authored-By trailers, then write "
                    "cerf/host/contributors_generated.txt, which cerf.rc "
                    "embeds as the ABOUT_CONTRIBUTORS resource.")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the generated list is stale "
                             "instead of rewriting it")
    args = parser.parse_args()

    from_git = git_contributors()
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

    sys.stdout.write("{} contributors ({} from git): {}\n".format(
        len(names), len(set(n.casefold() for n in from_git)), ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
