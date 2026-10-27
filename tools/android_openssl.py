from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from host_branch import ANDROID_AMD64, ANDROID_ARM64
from tool_log import tagged
from verified_download import fetch_verified

COMMIT = "b71f1470962019bd89534a2919f5925f93bc5779"
URL = "https://raw.githubusercontent.com/KDAB/android_openssl/{}/ssl_3/{}/{}"
OPENSSL_DIR = Path("third_party") / "android_openssl"
ABIS = {ANDROID_ARM64: "arm64-v8a", ANDROID_AMD64: "x86_64"}
LIBRARIES: Dict[str, Dict[str, str]] = {
    "arm64-v8a": {
        "libcrypto_3.so": "1e6c12ae0c2dadfe9d178d7f80f0ab248a1877a234066098bf5594e5205e5740",
        "libssl_3.so": "01d2bd0baac626efd3309f35f99c4b826dd9b885a7e4d14d5b12b3603d3a407f",
    },
    "x86_64": {
        "libcrypto_3.so": "bc4bdd31835659e639c2dc8f0a722342f51230074c23ee3dd6d1fa2353d72db1",
        "libssl_3.so": "2af32571317adf90fb7a007756a17dd15cd2469da9ebbd4e973883f8753369c1",
    },
}

say = tagged("OPENSSL")


def fetch(root: Path, branch_name: str) -> List[Path]:
    abi = ABIS[branch_name]
    folder = root / OPENSSL_DIR / COMMIT / abi
    return [fetch_verified(URL.format(COMMIT, abi, name), folder / name, sha256, say)
            for name, sha256 in LIBRARIES[abi].items()]
