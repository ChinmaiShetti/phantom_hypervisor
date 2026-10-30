import os
import tempfile
from pathlib import Path

import pytest

# Must run before `server.main` is imported anywhere: it builds a module-level app.
_SESSION_DIR = Path(tempfile.mkdtemp(prefix="phantom-test-"))
os.environ["DATA_DIR"] = str(_SESSION_DIR / "default")
os.environ["APP_ENV"] = "test"
os.environ["PHANTOM_ADMIN_SECRET"] = "test-admin-secret-123456"
os.environ.pop("PHANTOM_PRIVATE_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from security.signing import generate_private_key, private_key_to_b64  # noqa: E402
from server.config import Settings  # noqa: E402
from server.main import create_app  # noqa: E402

ADMIN = {"X-Admin-Secret": "test-admin-secret-123456"}


@pytest.fixture
def settings(tmp_path):
    return Settings(
        app_env="test",
        data_dir=tmp_path / "data",
        private_key_b64=private_key_to_b64(generate_private_key()),
        admin_secret=ADMIN["X-Admin-Secret"],
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c
