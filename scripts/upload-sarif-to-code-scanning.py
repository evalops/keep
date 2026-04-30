#!/usr/bin/env python3
"""Upload a SARIF file to GitHub Code Scanning without the CodeQL action."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request


def code_scanning_ref() -> str:
    ref = os.environ["GITHUB_REF"]
    if os.environ.get("GITHUB_EVENT_NAME") == "merge_group":
        with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as event_file:
            event = json.load(event_file)
        base_ref = event.get("merge_group", {}).get("base_ref", "")
        if base_ref.startswith("refs/heads/"):
            return base_ref
        if base_ref:
            return f"refs/heads/{base_ref}"
    if ref.startswith(("refs/heads/", "refs/pull/")):
        return ref
    raise ValueError(f"unsupported GITHUB_REF for Code Scanning SARIF upload: {ref}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif-file", required=True, type=Path)
    parser.add_argument("--category")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sarif_payload = base64.b64encode(gzip.compress(args.sarif_file.read_bytes())).decode(
        "ascii"
    )

    body = {
        "commit_sha": os.environ["GITHUB_SHA"],
        "ref": code_scanning_ref(),
        "sarif": sarif_payload,
        "checkout_uri": f"file://{os.environ['GITHUB_WORKSPACE']}",
    }
    if args.category:
        body["category"] = args.category

    request = urllib.request.Request(
        f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}/code-scanning/sarifs",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            print(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8")
        response_body_lower = response_body.lower()
        if error.code == 403 and (
            "advanced security must be enabled" in response_body_lower
            or "code scanning is not enabled" in response_body_lower
            or "code security must be enabled" in response_body_lower
        ):
            print("::warning::Code Security is not enabled; skipping SARIF upload.")
            return 0
        sys.stderr.write(response_body)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
