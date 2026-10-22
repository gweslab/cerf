#!/usr/bin/env python3
"""Publish a CERF release: run from the repo root as `python tools\\deploy.py`.

  --sha=<commit>  release the artifact built from that commit, not the newest
  --yes           take every confirmation as yes

The release is built from a CI artifact, never from the working tree - the tree
may already be ahead of what is being released. Every step asks first, so an
unexpected value can be answered with n and finished by hand."""
from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_branch
from changelog_card import artifact_card
from ci_release import (GITHUB_API, GITHUB_UPLOADS, REPO, Artifact, CiError,
                        changelog_markdown, github, latest_artifact,
                        load_credentials, post_discord, request, run_artifact)
from host_branch import HostBranch

DISCORD_CHANNEL_ID = "1517249750796206191"
RELEASE_WATCHERS_ROLE_ID = "1553511779789971606"
DOWNLOAD_URL = "https://cerf.cx/download/"


def confirm(question: str, assume_yes: bool) -> None:
    if assume_yes:
        print(f"{question} y")
        return
    answer = input(f"{question} [y/n] ").strip().lower()
    if not answer.startswith("y"):
        raise SystemExit("Stopped. Finish by hand from here.")


def existing_release(token: str, tag: str) -> Optional[dict]:
    try:
        return github(token, f"/repos/{REPO}/releases/tags/{tag}")
    except CiError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise


def download_artifact(token: str, artifact: Artifact, destination: Path) -> None:
    raw = request(
        f"{GITHUB_API}/repos/{REPO}/actions/artifacts/{artifact.id}/zip",
        {"Authorization": f"Bearer {token}",
         "Accept": "application/vnd.github+json"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    if destination.stat().st_size == 0:
        raise CiError(f"{destination} came back empty")


def packed_asset(token: str, artifact: Artifact) -> Path:
    wrapper = Path("tmp") / f"{artifact.name}.artifact.zip"
    download_artifact(token, artifact, wrapper)
    expected = f"{artifact.name}.zip"
    with zipfile.ZipFile(wrapper) as outer:
        names = outer.namelist()
        if names != [expected]:
            raise CiError(f"{artifact.name} holds {names}, not just {expected}")
        destination = Path("tmp") / expected
        destination.write_bytes(outer.read(expected))
    return destination


def release_asset(token: str, branch: HostBranch, artifact: Artifact) -> Path:
    if branch.packed_artifact:
        return packed_asset(token, artifact)
    archive = Path("tmp") / f"{artifact.name}.zip"
    download_artifact(token, artifact, archive)
    return archive


def create_release(token: str, artifact: Artifact, body: str) -> dict:
    return github(token, f"/repos/{REPO}/releases", "POST", {
        "tag_name": artifact.tag,
        "target_commitish": artifact.sha,
        "name": artifact.title,
        "body": body,
        "draft": False,
        "prerelease": False,
    })


def upload_asset(token: str, release_id: int, archive: Path) -> str:
    payload = json.loads(request(
        f"{GITHUB_UPLOADS}/repos/{REPO}/releases/{release_id}/assets"
        f"?name={archive.name}",
        {"Authorization": f"Bearer {token}",
         "Accept": "application/vnd.github+json"},
        "POST", archive.read_bytes(), "application/zip").decode("utf-8"))
    return payload["browser_download_url"]


def release_message(artifact: Artifact) -> str:
    return (f"**v{artifact.series} build {artifact.run_number}** released "
            f"<@&{RELEASE_WATCHERS_ROLE_ID}>\n"
            f"[Download]({DOWNLOAD_URL}) · "
            f"[Release](https://github.com/{REPO}/releases/tag/{artifact.tag}) · "
            f"[CI build]({artifact.run_url}) · "
            f"[`{artifact.sha[:7]}`]({artifact.commit_url})")


def main(argv: List[str]) -> int:
    assume_yes = "--yes" in argv
    sha = next((a.partition("=")[2] for a in argv if a.startswith("--sha=")), None)
    token, secret = load_credentials()

    artifact = latest_artifact(token, sha)
    print(f"\nArtifact        : {artifact.name}")
    print(f"  version / tag : {artifact.version} -> {artifact.tag}")
    print(f"  release title : {artifact.title}")
    print(f"  branch / sha  : {artifact.branch} / {artifact.sha[:7]}")
    print(f"  built         : {artifact.created_at}")
    print(f"  size          : {artifact.size / 1024 / 1024:.1f} MB")
    confirm(f"Release {artifact.tag} from this artifact?", assume_yes)

    if existing_release(token, artifact.tag) is not None:
        raise CiError(f"release {artifact.tag} already exists")

    body = changelog_markdown(artifact.series)
    print(f"\nChangelog for v{artifact.series}:\n{body}\n")
    confirm("Use this as the release description?", assume_yes)

    card = artifact_card(token, artifact, "release")
    print(f"  announcement card rendered ({len(card) // 1024} KB)")

    archives = []
    for branch in host_branch.all_branches():
        build = run_artifact(token, artifact.run_id, branch.platform_dir)
        print(f"\nDownloading {build.name} ...")
        archives.append(release_asset(token, branch, build))
    for path in archives:
        print(f"  {path} ({path.stat().st_size / 1024 / 1024:.1f} MB)")
    confirm(f"Publish tag {artifact.tag} at {artifact.sha[:7]} with these assets?",
            assume_yes)

    release = create_release(token, artifact, body)
    print(f"  release created: {release['html_url']}")
    for path in archives:
        print(f"  uploading {path.name} ...")
        print(f"  asset: {upload_asset(token, release['id'], path)}")

    confirm(f"\nPost the {artifact.tag} announcement to Discord?", assume_yes)
    post_discord(secret, DISCORD_CHANNEL_ID, release_message(artifact),
                 ping_role=RELEASE_WATCHERS_ROLE_ID, image=card)
    print("  posted.\n")
    print(f"Released {artifact.tag}: {release['html_url']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except CiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
