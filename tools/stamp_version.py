#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from pathlib import Path

import host_branch
from header_defines import int_define

VERSION_PATH = Path("cerf-qt/version.h")
BUILD_WORD_MODULUS = 65536


def artifact_name(version: str, sha: str, branch: host_branch.HostBranch) -> str:
    return "CERF-{}-{}-{}".format(version, sha, host_branch.release_marker(branch))


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="Stamp version.h with CI build info.")
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--host-branch", default=None)
    args = parser.parse_args(argv)
    job_branch = host_branch.by_name(args.host_branch) if args.host_branch else None

    text = VERSION_PATH.read_text(encoding="utf-8")
    version = ".".join(str(int_define(VERSION_PATH, "CERF_VERSION_" + part)) for part in ("MAJOR", "MINOR", "PATCH"))
    sha = args.sha[:7]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M") + " UTC"
    word = args.run % BUILD_WORD_MODULUS

    replacements = (
        (r"^#define\s+CERF_VERSION_BUILD\s+\d+", "#define CERF_VERSION_BUILD      {}".format(args.run)),
        (r"^#define\s+CERF_VERSION_BUILD_WORD\s+\d+", "#define CERF_VERSION_BUILD_WORD {}".format(word)),
        (r"^#define\s+CERF_VERSION_DATE\s+.*$", '#define CERF_VERSION_DATE       "{}"'.format(stamp)),
        (r"^#define\s+CERF_VERSION_SHA\s+.*$", '#define CERF_VERSION_SHA        "{}"'.format(sha)),
    )
    for pattern, line in replacements:
        text = re.sub(pattern, lambda _m, line=line: line, text, flags=re.MULTILINE)
    VERSION_PATH.write_bytes(text.encode("utf-8"))

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        lines = ["version=" + version, "sha=" + sha]
        for branch in host_branch.ci_branches():
            lines.append("artifact-{}={}".format(branch.name, artifact_name(version, sha, branch)))
            lines.append("frontend-{}={}".format(branch.name, branch.frontend))
        if job_branch is not None:
            lines.append("artifact=" + artifact_name(version, sha, job_branch))
            lines.append("out=" + host_branch.output_dir(Path("."), "Release", job_branch).as_posix())
            lines.append("frontend=" + job_branch.frontend)
        with open(output, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    print("Stamped: {} build {} (word {}), {}, {}".format(version, args.run, word, stamp, sha))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
