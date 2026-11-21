#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ci_release import USER_AGENT, CiError, env
from http_request import request
from product_facts import ANDROID_PACKAGE_NAME
from tool_cli import option, run_main

API_ROOT = "https://androidpublisher.googleapis.com"
APP_PATH = "/androidpublisher/v3/applications/" + ANDROID_PACKAGE_NAME
SCOPE = "https://www.googleapis.com/auth/androidpublisher"
KEY_VARIABLE = "PLAY_SERVICE_ACCOUNT_JSON"
PRODUCTION_TRACK = "production"
CANCEL_IN_REVIEW = "CANCEL_IN_REVIEW_AND_SUBMIT"
ERROR_IF_IN_REVIEW = "ERROR_IF_IN_REVIEW"
IN_REVIEW_REASON = "CHANGES_ALREADY_IN_REVIEW"
IN_REVIEW_STATE = "RELEASE_LIFECYCLE_STATE_IN_REVIEW"
JSON_TYPE = "application/json"


def access_token() -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account
    info = json.loads(env(KEY_VARIABLE))
    credentials = service_account.Credentials.from_service_account_info(info, scopes=[SCOPE])
    credentials.refresh(Request())
    return credentials.token


def call(token: str, method: str, url: str, body: Optional[bytes] = None,
         content_type: Optional[str] = None) -> dict:
    raw = request(url, {"Authorization": "Bearer " + token}, CiError, USER_AGENT, method, body,
                  content_type)
    return json.loads(raw) if raw else {}


def in_review_refusal(exc: CiError) -> bool:
    try:
        details = json.loads(exc.body)["error"]["details"]
    except (ValueError, KeyError, TypeError):
        return False
    return any(isinstance(d, dict) and d.get("reason") == IN_REVIEW_REASON for d in details)


def production_in_review(token: str) -> bool:
    releases = call(token, "GET", "{}{}/tracks/{}/releases".format(
        API_ROOT, APP_PATH, PRODUCTION_TRACK)).get("releases", [])
    return any(r.get("releaseLifecycleState") == IN_REVIEW_STATE for r in releases)


def commit(token: str, edits: str, edit: str, behavior: str) -> None:
    call(token, "POST", "{}/{}:commit?changesInReviewBehavior={}".format(edits, edit, behavior), b"")


def publish(token: str, payload: bytes, track: str) -> Optional[str]:
    edits = API_ROOT + APP_PATH + "/edits"
    edit = call(token, "POST", edits, b"{}", JSON_TYPE)["id"]
    print("Uploading the app bundle ({:.1f} MB) ...".format(len(payload) / 1024 / 1024))
    uploaded = call(token, "POST", "{}/upload{}/edits/{}/bundles?uploadType=media".format(
        API_ROOT, APP_PATH, edit), payload, "application/octet-stream")
    version_code = str(uploaded["versionCode"])
    release = {"track": track, "releases": [{"versionCodes": [version_code], "status": "completed"}]}
    call(token, "PUT", "{}/{}/tracks/{}".format(edits, edit, track),
         json.dumps(release).encode("utf-8"), JSON_TYPE)
    if track == PRODUCTION_TRACK:
        commit(token, edits, edit, CANCEL_IN_REVIEW)
        return version_code
    try:
        commit(token, edits, edit, ERROR_IF_IN_REVIEW)
    except CiError as exc:
        if not in_review_refusal(exc):
            raise
        if production_in_review(token):
            print("A production release is in review on Google Play, so version code {} "
                  "is not released on the {} track".format(version_code, track))
            return None
        commit(token, edits, edit, CANCEL_IN_REVIEW)
    return version_code


def main(argv: List[str]) -> int:
    bundle = option(argv, "--bundle")
    track = option(argv, "--track")
    if not bundle or not track:
        raise CiError("usage: publish_play.py --bundle=<path> --track=<track> [--attempts=<n>]")
    attempts = int(option(argv, "--attempts") or "1")
    payload = Path(bundle).read_bytes()

    token = access_token()
    for attempt in range(1, attempts + 1):
        try:
            version_code = publish(token, payload, track)
            break
        except CiError as exc:
            if attempt == attempts:
                raise
            print("Attempt {} failed, starting a new edit: {}".format(attempt, exc))
    if version_code is not None:
        print("Released version code {} on the {} track".format(version_code, track))
    return 0


if __name__ == "__main__":
    run_main(main, (CiError,))
