#!/usr/bin/env python3
"""Upload a SARIF file to GitHub Code Scanning without the CodeQL action."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import time
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


def request_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def artifact_uri(run: dict[str, object], artifact_location: object) -> object:
    if not isinstance(artifact_location, dict):
        return None
    uri = artifact_location.get("uri")
    if uri:
        return uri
    index = artifact_location.get("index")
    artifacts = run.get("artifacts")
    if not isinstance(index, int) or not isinstance(artifacts, list):
        return None
    if index < 0 or index >= len(artifacts):
        return None
    artifact = artifacts[index]
    if not isinstance(artifact, dict):
        return None
    location = artifact.get("location")
    if not isinstance(location, dict):
        return None
    return location.get("uri")


def result_location_key(result: dict[str, object], run: dict[str, object]) -> dict[str, object]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return {}
    first_location = locations[0]
    if not isinstance(first_location, dict):
        return {}
    physical_location = first_location.get("physicalLocation")
    if not isinstance(physical_location, dict):
        return {}
    region = physical_location.get("region")
    if not isinstance(region, dict):
        region = {}

    return {
        "uri": artifact_uri(run, physical_location.get("artifactLocation")),
        "startLine": region.get("startLine"),
        "startColumn": region.get("startColumn"),
        "endLine": region.get("endLine"),
        "endColumn": region.get("endColumn"),
    }


def result_fingerprint(result: dict[str, object], run: dict[str, object]) -> str:
    key = {
        "ruleId": result.get("ruleId"),
        "message": result.get("message"),
        "location": result_location_key(result, run),
    }
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sarif_upload_bytes(path: Path) -> bytes:
    sarif = json.loads(path.read_text(encoding="utf-8"))
    for run in sarif.get("runs", []):
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            if result.get("partialFingerprints"):
                continue
            result["partialFingerprints"] = {
                "primaryLocationLineHash": result_fingerprint(result, run)
            }
    return json.dumps(sarif, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def wait_for_sarif_processing(sarif_id: str) -> None:
    deadline = time.monotonic() + 120
    status_url = (
        f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}"
        f"/code-scanning/sarifs/{sarif_id}"
    )
    while True:
        request = urllib.request.Request(status_url, headers=request_headers())
        with urllib.request.urlopen(request) as response:
            status_body = json.loads(response.read().decode("utf-8"))
        processing_status = status_body.get("processing_status")
        if processing_status == "complete":
            print(json.dumps(status_body))
            return
        if processing_status == "failed":
            raise RuntimeError(f"SARIF processing failed: {json.dumps(status_body)}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for SARIF processing: {json.dumps(status_body)}")
        print(f"SARIF processing status is {processing_status}; waiting...")
        time.sleep(5)


def main() -> int:
    args = parse_args()
    sarif_payload = base64.b64encode(
        gzip.compress(sarif_upload_bytes(args.sarif_file))
    ).decode("ascii")

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
        headers=request_headers(),
    )
    try:
        with urllib.request.urlopen(request) as response:
            response_body = json.loads(response.read().decode("utf-8"))
            print(json.dumps(response_body))
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
    sarif_id = response_body.get("id")
    if sarif_id:
        wait_for_sarif_processing(str(sarif_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
