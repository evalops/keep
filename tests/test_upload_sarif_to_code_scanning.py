from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import urllib.error


def load_upload_sarif_module():
    module_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "upload-sarif-to-code-scanning.py"
    )
    spec = importlib.util.spec_from_file_location("upload_sarif_to_code_scanning", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_polling_http_error_can_skip_when_code_scanning_is_disabled(capsys):
    module = load_upload_sarif_module()
    error = urllib.error.HTTPError(
        "https://api.github.com/repos/evalops/keep/code-scanning/sarifs/1",
        403,
        "Forbidden",
        {},
        io.BytesIO(b'{"message":"Code scanning is not enabled"}'),
    )

    assert module.handle_code_scanning_http_error(error) is None
    assert "Code Security is not enabled" in capsys.readouterr().out


def test_non_code_scanning_http_error_is_reraised(capsys):
    module = load_upload_sarif_module()
    error = urllib.error.HTTPError(
        "https://api.github.com/repos/evalops/keep/code-scanning/sarifs/1",
        500,
        "Server Error",
        {},
        io.BytesIO(b'{"message":"temporary outage"}'),
    )

    try:
        module.handle_code_scanning_http_error(error)
    except urllib.error.HTTPError as raised:
        assert raised is error
    else:
        raise AssertionError("expected HTTPError to be reraised")
    assert "temporary outage" in capsys.readouterr().err
