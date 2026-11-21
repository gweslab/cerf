#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

import host_branch
import version_header
from github_output import write_github_output

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

    version = ".".join(map(str, version_header.release_numbers()))
    sha = args.sha[:7]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M") + " UTC"
    word = args.run % BUILD_WORD_MODULUS

    version_header.rewrite({
        "build": str(args.run),
        "build_word": str(word),
        "date": '"{}"'.format(stamp),
        "sha": '"{}"'.format(sha),
    })

    lines = ["version=" + version, "sha=" + sha]
    for branch in host_branch.ci_branches():
        lines.append("artifact-{}={}".format(branch.name, artifact_name(version, sha, branch)))
        lines.append("frontend-{}={}".format(branch.name, branch.frontend))
    if job_branch is not None:
        lines.append("artifact=" + artifact_name(version, sha, job_branch))
        lines.append("out=" + host_branch.output_dir(Path("."), "Release", job_branch).as_posix())
        lines.append("frontend=" + job_branch.frontend)
        if job_branch.store_bundle:
            lines.append("bundle=" + job_branch.store_bundle)
    write_github_output(lines)
    print("Stamped: {} build {} (word {}), {}, {}".format(version, args.run, word, stamp, sha))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
