from __future__ import annotations

import urllib.error
import urllib.request
from typing import Optional, Type


class AuthStrippingRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            for name in [h for h in new.headers if h.lower() == "authorization"]:
                del new.headers[name]
        return new


def request(url: str, headers: dict, error: Type[Exception], user_agent: str, method: str = "GET",
            body: Optional[bytes] = None, content_type: Optional[str] = None) -> bytes:
    headers = dict(headers)
    headers["User-Agent"] = user_agent
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(AuthStrippingRedirect)
    try:
        with opener.open(req, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise error(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise error(f"{method} {url} unreachable: {exc}") from exc
