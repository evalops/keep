import os
import sys

if any("pytest" in arg for arg in sys.argv):
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from .main import app  # re-export for tests

__all__ = ["app"]
