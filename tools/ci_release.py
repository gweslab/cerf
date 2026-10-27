from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import changelog
import host_branch

REPO = "gweslab/cerf"
GITHUB_API = "https://api.github.com"
GITHUB_UPLOADS = "https://uploads.github.com"
DISCORD_API = "https://discord.com/api/v10"
DISCORD_MESSAGE_LIMIT = 2000
DISCORD_SUPPRESS_EMBEDS = 1 << 2

ARTIFACT_NAME = re.compile(r"^CERF-(\d+)\.(\d+)\.(\d+)-([0-9a-f]+)-" + re.escape(host_branch.RELEASE_PREFIX)
                           + r"([A-Za-z0-9-]+)$")
WIN32_PLATFORM = host_branch.by_name(host_branch.WIN32_X86).platform_dir
CHANGELOG_PATH = Path("docs/changelog.yml")
ENV_PATH = Path(".env")
USER_AGENT = "CERF deploy"


class CiError(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifact:
    id: int
    name: str
    size: int
    created_at: str
    branch: str
    sha: str
    run_id: int
    run_number: int
    version: str
    series: str
    platform: str

    @property
    def tag(self) -> str:
        return f"{self.version}.{self.run_number}"

    @property
    def title(self) -> str:
        return f"{self.series} (build {self.run_number})"

    @property
    def run_url(self) -> str:
        return f"https://github.com/{REPO}/actions/runs/{self.run_id}"

    @property
    def commit_url(self) -> str:
        return f"https://github.com/{REPO}/commit/{self.sha}"

    @property
    def download_url(self) -> str:
        return f"{host_branch.CI_BASE_URL}/{self.name}.zip"


def load_env() -> dict:
    values = {}
    if ENV_PATH.is_file():
        for line in ENV_PATH.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def load_credentials() -> tuple:
    values = load_env()

    def pick(*names: str) -> str:
        for name in names:
            value = os.environ.get(name) or values.get(name)
            if value:
                return value
        raise CiError(
            f"no {' / '.join(names)} in the environment or {ENV_PATH}")

    return pick("GITHUB_TOKEN", "GH_TOKEN"), pick("DISCORD_SECRET")


class AuthStrippingRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            for name in [h for h in new.headers if h.lower() == "authorization"]:
                del new.headers[name]
        return new


def request(url: str, headers: dict, method: str = "GET",
            body: Optional[bytes] = None, content_type: Optional[str] = None):
    headers = dict(headers)
    headers["User-Agent"] = USER_AGENT
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(AuthStrippingRedirect)
    try:
        with opener.open(req, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise CiError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CiError(f"{method} {url} unreachable: {exc}") from exc


def github(token: str, path: str, method: str = "GET",
           payload: Optional[dict] = None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    raw = request(GITHUB_API + path,
                  {"Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github+json"},
                  method, body, "application/json" if body else None)
    return json.loads(raw.decode("utf-8")) if raw else {}


def _artifact(item: dict, platform: str) -> Optional[Artifact]:
    if item.get("expired"):
        return None
    match = ARTIFACT_NAME.match(item.get("name", ""))
    if not match or match.group(5) != platform:
        return None
    run = item.get("workflow_run") or {}
    major, minor, patch, name_sha, _platform = match.groups()
    return Artifact(
        id=item["id"], name=item["name"], size=item["size_in_bytes"],
        created_at=item["created_at"],
        branch=run.get("head_branch") or "?",
        sha=run.get("head_sha") or name_sha,
        run_id=run.get("id") or 0, run_number=0,
        version=f"{major}.{minor}.{patch}", series=f"{major}.{minor}",
        platform=platform)


def _with_run_number(token: str, artifact: Artifact) -> Artifact:
    if not artifact.run_id:
        raise CiError(f"artifact {artifact.name} has no workflow run, "
                      "so it has no build number")
    payload = github(token, f"/repos/{REPO}/actions/runs/{artifact.run_id}")
    number = payload.get("run_number")
    if not isinstance(number, int) or isinstance(number, bool):
        raise CiError(f"run {artifact.run_id} reports no run_number")
    return replace(artifact, run_number=number)


def latest_artifact(token: str, sha: Optional[str] = None,
                    platform: str = WIN32_PLATFORM) -> Artifact:
    payload = github(token, f"/repos/{REPO}/actions/artifacts?per_page=100")
    for item in payload.get("artifacts", []):
        artifact = _artifact(item, platform)
        if artifact is None:
            continue
        if sha and not artifact.sha.startswith(sha) and not sha.startswith(artifact.sha):
            continue
        return _with_run_number(token, artifact)
    where = f" built from {sha[:7]}" if sha else ""
    raise CiError(f"no unexpired {host_branch.RELEASE_PREFIX}{platform} artifact{where} found")


def run_artifact(token: str, run_id: int, platform: str = WIN32_PLATFORM,
                 attempts: int = 12, delay: int = 10) -> Artifact:
    for attempt in range(attempts):
        payload = github(
            token, f"/repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100")
        for item in payload.get("artifacts", []):
            artifact = _artifact(item, platform)
            if artifact is not None:
                return _with_run_number(token, artifact)
        if attempt + 1 < attempts:
            print(f"  artifact of run {run_id} not listed yet, retrying in {delay}s")
            time.sleep(delay)
    raise CiError(f"run {run_id} published no {host_branch.RELEASE_PREFIX}{platform} artifact")


def changelog_markdown(tag: str, fallback: Optional[str] = None) -> str:
    if not CHANGELOG_PATH.is_file():
        raise CiError(f"{CHANGELOG_PATH} not found; run from the repo root")
    entry = changelog.entry_for(tag)
    if entry is None or not entry["groups"]:
        if fallback is not None:
            return fallback
        raise CiError(f"{CHANGELOG_PATH} has no entries for v{tag}")
    return changelog.render_markdown(entry["groups"])


def latest_release(token: str) -> Tuple[str, str]:
    release = github(token, f"/repos/{REPO}/releases/latest")
    tag = release.get("tag_name")
    if not tag:
        raise CiError("the latest release reports no tag")
    sha = github(token, f"/repos/{REPO}/commits/{tag}").get("sha")
    if not sha:
        raise CiError(f"release tag {tag} resolves to no commit")
    return release.get("name") or tag, sha


def _multipart(payload: dict, image: bytes, filename: str) -> Tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    head = (f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="payload_json"\r\n'
            "Content-Type: application/json\r\n\r\n"
            f"{json.dumps(payload)}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files[0]"; '
            f'filename="{filename}"\r\n'
            "Content-Type: image/png\r\n\r\n").encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    return head + image + tail, f"multipart/form-data; boundary={boundary}"


def post_discord(secret: str, channel_id: str, content: str,
                 ping_role: Optional[str] = None,
                 image: Optional[bytes] = None,
                 filename: str = "changelog.png") -> None:
    if len(content) > DISCORD_MESSAGE_LIMIT:
        raise CiError(
            f"the Discord message is {len(content)} characters, over the "
            f"{DISCORD_MESSAGE_LIMIT} limit")
    mentions = {"parse": [], "roles": [ping_role] if ping_role else []}
    payload = {"content": content,
               "flags": DISCORD_SUPPRESS_EMBEDS,
               "allowed_mentions": mentions}
    url = f"{DISCORD_API}/channels/{channel_id}/messages"
    headers = {"Authorization": f"Bot {secret}"}
    if image is None:
        request(url, headers, "POST", json.dumps(payload).encode("utf-8"),
                "application/json")
        return
    payload["attachments"] = [{"id": 0, "filename": filename}]
    body, content_type = _multipart(payload, image, filename)
    request(url, headers, "POST", body, content_type)
