#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_branch
from changelog_card import artifact_card
from host_branch import HostBranch
from ci_release import (Artifact, CiError, load_credentials, post_discord,
                        run_artifact)

QA_CHANNEL_ID = "1537263681228771349"
QA_ROLE_ID = "1537262210118852708"


def message(builds: List[Tuple[HostBranch, Artifact]], release_candidate: bool) -> str:
    run = builds[0][1]
    title = f"**v{run.series} build {run.run_number}**"
    if release_candidate:
        headline = f"{title} [release candidate] available <@&{QA_ROLE_ID}>"
    else:
        headline = f"{title} [unstable] available"
    downloads = " · ".join(f"[{branch.label}]({build.download_url})"
                           for branch, build in builds)
    return (f"{headline}\n"
            f"Download: {downloads} · "
            f"[CI build]({run.run_url}) · "
            f"[`{run.sha[:7]}`]({run.commit_url})")


def main(argv: List[str]) -> int:
    run_id = next((a.partition("=")[2] for a in argv
                   if a.startswith("--run-id=")), "")
    if not run_id.isdigit():
        raise CiError("--run-id=<id> is required")
    release_candidate = "--rc" in argv

    token, secret = load_credentials()
    builds = [(branch, run_artifact(token, int(run_id), branch.platform_dir))
              for branch in host_branch.all_branches()]
    run = builds[0][1]
    print(f"\nRun             : {run.run_url}")
    print(f"  version / tag : {run.version} -> {run.tag}")
    print(f"  branch / sha  : {run.branch} / {run.sha[:7]}")
    for branch, build in builds:
        print(f"  {branch.label.lower():<14}: {build.download_url}")

    kind = "candidate" if release_candidate else "unstable"
    card = artifact_card(token, run, kind)
    content = message(builds, release_candidate)
    print(f"\n{content}\n  card: {len(card) // 1024} KB\n")
    post_discord(secret, QA_CHANNEL_ID, content,
                 ping_role=QA_ROLE_ID if release_candidate else None,
                 image=card)
    print(f"Announced run {run_id} in channel {QA_CHANNEL_ID}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except CiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
